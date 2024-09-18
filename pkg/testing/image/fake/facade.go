package fake

import (
	"context"
	"sync"

	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/openshift/multiarch-tuning-operator/pkg/image"
)

var (
	singletonImageFacade *Facade
	// once is used for lazy initialization of the singletonImageFacade
	once sync.Once
)

type Facade struct {
	inspectionCache image.ICache
}

func (i *Facade) GetCompatibleArchitecturesSet(ctx context.Context, imageReference string,
	secrets [][]byte) (architectures sets.Set[string], err error) {
	return i.inspectionCache.GetCompatibleArchitecturesSet(ctx, imageReference, secrets)
}

func newImageFacade() *Facade {
	inspectionCache := newCacheProxy()
	return &Facade{
		inspectionCache: inspectionCache,
	}
}

func FacadeSingleton() *Facade {
	once.Do(func() {
		singletonImageFacade = newImageFacade()
	})
	return singletonImageFacade
}
