/*
Copyright 2023 Red Hat, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package image

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"

	"k8s.io/apimachinery/pkg/util/sets"
)

type cacheProxy struct {
	registryInspector        IRegistryInspector
	imageRefsArchitectureMap map[string]sets.Set[string]
	mutex                    sync.Mutex
}

func (c *cacheProxy) GetCompatibleArchitecturesSet(ctx context.Context, imageReference string, secrets [][]byte) (sets.Set[string], error) {
	authJson, err := c.registryInspector.marshaledImagePullSecrets(secrets)
	if err != nil {
		return nil, err
	}

	if architectures, ok := c.imageRefsArchitectureMap[computeSHA256Hash(imageReference, authJson)]; ok {
		return architectures, nil
	}
	architectures, err := c.registryInspector.GetCompatibleArchitecturesSet(ctx, imageReference, secrets)
	if err != nil {
		return nil, err
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.imageRefsArchitectureMap[computeSHA256Hash(imageReference, authJson)] = architectures
	return architectures, nil
}

func (c *cacheProxy) GetRegistryInspector() IRegistryInspector {
	return c.registryInspector
}

// Problems
//  1. misses a cache eviction policy
//  2. it may need a few further fixes to avoid leaking metadata of images when the inspection
//     happens with different pull secrets
func newCacheProxy() *cacheProxy {
	return &cacheProxy{
		imageRefsArchitectureMap: map[string]sets.Set[string]{},
		registryInspector:        newRegistryInspector(),
	}
}

// TODO: eviction policy
// return the value insted of the key
func computeSHA256Hash(imageReference string, secrets []byte) string {
	hash := sha256.Sum256(append([]byte(imageReference)[:], secrets[:]...))
	return hex.EncodeToString(hash[:])
}
