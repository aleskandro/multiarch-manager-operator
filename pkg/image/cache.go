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
	"k8s.io/apimachinery/pkg/util/sets"
	"sync"
)

type cacheProxy struct {
	registryInspector        IRegistryInspector
	imageRefsArchitectureMap map[string]sets.Set[string]
	mutex                    sync.Mutex
}

func (c *cacheProxy) GetCompatibleArchitecturesSet(ctx context.Context, imageReference string, secrets [][]byte) (sets.Set[string], error) {
	if c.imageRefsArchitectureMap[imageReference] != nil {
		return c.imageRefsArchitectureMap[imageReference], nil
	}
	architectures, err := c.registryInspector.GetCompatibleArchitecturesSet(ctx, imageReference, secrets)
	if err != nil {
		return nil, err
	}
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.imageRefsArchitectureMap[imageReference] = architectures
	return architectures, nil
}

func newCache() ICache {
	return &cacheProxy{
		imageRefsArchitectureMap: map[string]sets.Set[string]{},
		registryInspector:        newRegistryInspector(),
	}
}

// TODO: eviction policy
