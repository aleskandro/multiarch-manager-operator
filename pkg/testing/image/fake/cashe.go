package fake

import (
	"context"
	"errors"

	"k8s.io/apimachinery/pkg/util/sets"
)

type cacheProxy struct {
	registryInspector        *registryInspector
	imageRefsArchitectureMap map[string]sets.Set[string]
}

func (c *cacheProxy) GetCompatibleArchitecturesSet(ctx context.Context, imageReference string,
	secrets [][]byte) (supportedArchitectures sets.Set[string], err error) {
	// we expect the imageReference to start with `//`. Let's remove it
	imageReference = imageReference[2:]
	if archSet, ok := MockImagesArchitectureMap()[imageReference]; ok {
		return archSet, nil
	}
	// The image is not in the mock map, return an empty set (emulating an image not found or any other error)
	return nil, errors.New("image not found")
}

func newCacheProxy() *cacheProxy {
	return &cacheProxy{
		imageRefsArchitectureMap: map[string]sets.Set[string]{},
		registryInspector:        newRegistryInspector(),
	}
}
