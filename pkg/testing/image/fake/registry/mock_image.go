package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/containers/image/v5/docker"
	"github.com/containers/image/v5/manifest"
	"github.com/containers/image/v5/pkg/blobinfocache/none"
	"github.com/containers/image/v5/types"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"

	"k8s.io/apimachinery/pkg/util/sets"
)

// MockImage is a mock image that can be pushed to a registry. It carries only the information needed
// for the tests. The final image is either a single architecture image or a manifest list and has
// no data in the layers. The methods of the MockImage should not be considered for production use and are
// only meant to facilitate the tests of this operator.
type MockImage struct {
	Architectures sets.Set[string]
	MediaType     string
	Repository    string
	Name          string
	Tag           string
	Labels        map[string]string
	partial       bool
	destination   *types.ImageDestination
}

// GetUrl returns the url of the image
func (i *MockImage) GetUrl() string {
	return fmt.Sprintf("%s/%s/%s:%s", url, i.Repository, i.Name, i.Tag)
}

// getConfigMediaType returns the media type of the config blob given the media type of the manifest(list)
func (i *MockImage) getConfigMediaType() string {
	switch i.MediaType {
	case imgspecv1.MediaTypeImageManifest:
		return imgspecv1.MediaTypeImageConfig
	case manifest.DockerV2Schema2MediaType:
		return manifest.DockerV2Schema2ConfigMediaType
	}
	panic(fmt.Sprintf("MediaType %s not supported", i.MediaType))
}

// getDestination creates or returns the destination of the image
func (i *MockImage) getDestination(ctx context.Context, authFile string) (dst types.ImageDestination, err error) {
	if i.destination != nil {
		return *i.destination, nil
	}
	ref, err := docker.ParseReference(fmt.Sprintf("//%s", i.GetUrl()))
	if err != nil {
		log.Error(err, "Error parsing the image reference for the image")
		return
	}
	sys := &types.SystemContext{
		AuthFilePath:             authFile,
		DockerPerHostCertDirPath: perRegistryCertDirPath,
	}
	dstV, err := ref.NewImageDestination(ctx, sys)
	if err != nil {
		log.Error(err, "Error creating the image destination")
		return
	}
	i.destination = &dstV
	return dstV, nil
}

// prepareSingleArchImage creates and push the config blob and the manifestObj for a single architecture image
func (i *MockImage) prepareSingleArchImage(ctx context.Context, dst *types.ImageDestination) (
	manifestDigest *digest.Digest, manifestJsonBytes []byte, err error) {
	// Single architecture images or partial manifests for manifestObj lists
	// We expect the architecture set to be a singleton
	arch, _ := i.Architectures.PopAny()
	labelsJsonBytes, _ := json.Marshal(i.Labels)
	configData := []byte(fmt.Sprintf(`{"architecture":"%s","os":"linux","config":{"Labels":%s}}`, arch, string(labelsJsonBytes)))
	configDataDigest, err := manifest.Digest(configData)
	if err != nil {
		log.Error(err, "Error computing the digest of the image config data")
		return nil, nil, err
	}
	manifestObj := imgspecv1.Manifest{
		Versioned: specs.Versioned{
			SchemaVersion: 2,
		},
		MediaType: i.MediaType,
		Config: imgspecv1.Descriptor{
			MediaType: i.getConfigMediaType(),
			Digest:    configDataDigest,
			Size:      int64(len(configData)),
		},
	}
	manifestJsonBytes, err = json.Marshal(manifestObj)
	if err != nil {
		log.Error(err, "Error marshalling the manifestObj")
		return nil, nil, err
	}
	manifestDigestV, err := manifest.Digest(manifestJsonBytes)
	if err != nil {
		log.Error(err, "Error computing the digest of the manifestObj")
		return nil, nil, err
	}
	manifestDigest = &manifestDigestV
	// Push config blob to registry
	_, err = (*dst).PutBlob(ctx,
		bytes.NewReader(configData),
		types.BlobInfo{Digest: "", Size: int64(len(configData))},
		none.NoCache, false,
	)
	if err != nil {
		fmt.Printf("Error pushing image: %v\n", err)
		return nil, nil, err
	}
	return
}

// prepareManifestList creates and push the config blob and the manifestObj for a manifest list
func (i *MockImage) prepareManifestList(ctx context.Context, authFile string, dst *types.ImageDestination) (
	manifestDigest *digest.Digest, manifestJsonBytes []byte, err error) {
	// The Docker and OCI manifest list json are compatible for the current cases
	list := imgspecv1.Index{
		Versioned: specs.Versioned{
			SchemaVersion: 2,
		},
		Manifests: []imgspecv1.Descriptor{},
		MediaType: i.MediaType,
	}
	for _, arch := range i.Architectures.UnsortedList() {
		singleArchManifestMediaType := imgspecv1.MediaTypeImageManifest
		if i.MediaType == manifest.DockerV2ListMediaType {
			singleArchManifestMediaType = manifest.DockerV2Schema2MediaType
		}
		singleArchImageLength, singleArchImageDigest, err := (&MockImage{
			Architectures: sets.New[string](arch),
			MediaType:     singleArchManifestMediaType,
			Repository:    i.Repository,
			Name:          i.Name,
			Tag:           i.Tag,
			partial:       true,
			destination:   i.destination,
		}).pushImage(ctx, authFile)
		if err != nil {
			log.Error(err, "Error pushing the single arch image")
			return nil, nil, err
		}
		list.Manifests = append(list.Manifests, imgspecv1.Descriptor{
			MediaType: singleArchManifestMediaType,
			Digest:    *singleArchImageDigest,
			Size:      singleArchImageLength,
			Platform: &imgspecv1.Platform{
				Architecture: arch,
				OS:           "linux",
			},
		})
	}
	// marshal the manifest list
	manifestJsonBytes, err = json.Marshal(list)
	if err != nil {
		log.Error(err, "Error marshalling the manifest list")
		return nil, nil, err
	}
	manifestDigestV, err := manifest.Digest(manifestJsonBytes)
	if err != nil {
		log.Error(err, "Error computing the singleArchImageDigest of the manifest")
	}
	manifestDigest = &manifestDigestV
	return
}

// pushImage pushes the image to the registry. Note that if the image is a manifest list, the method will
// recursively call itself to push the single manifest of the list through the prepareManifestList method.
func (i *MockImage) pushImage(ctx context.Context, authFile string) (length int64, manifestDigest *digest.Digest, err error) {
	dst, err := i.getDestination(ctx, authFile)
	if err != nil {
		log.Error(err, "Error creating the image destination")
		return
	}
	// Create and push the config data blob and set up the manifestObj
	var manifestJsonBytes []byte
	switch i.MediaType {
	case imgspecv1.MediaTypeImageManifest, manifest.DockerV2Schema2MediaType:
		manifestDigest, manifestJsonBytes, err = i.prepareSingleArchImage(ctx, &dst)
		if err != nil {
			return length, nil, err
		}
	case manifest.DockerV2ListMediaType, imgspecv1.MediaTypeImageIndex:
		// NOTE: prepareManifestList will recursively call pushImage to push the single manifests of the list
		manifestDigest, manifestJsonBytes, err = i.prepareManifestList(ctx, authFile, &dst)
		if err != nil {
			return length, nil, err
		}
	}
	length = int64(len(manifestJsonBytes))
	var instanceDigest *digest.Digest
	if i.partial {
		// If the MockImage comes from recursion, to push the single manifest of a manifest list
		instanceDigest = manifestDigest
	}
	err = dst.PutManifest(ctx, manifestJsonBytes, instanceDigest)
	if err != nil {
		return length, nil, err
	}
	err = dst.Commit(ctx, nil)
	if err != nil {
		return length, nil, err
	}
	return length, manifestDigest, nil
}

func (i *MockImage) Equals(other *MockImage) bool {
	return i.GetUrl() == other.GetUrl()
}
