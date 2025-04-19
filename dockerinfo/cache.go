package dockerinfo

import (
	"time"

	"github.com/fanjindong/go-cache"
)

type LocalCaches struct {
   RefreshProccessCache  cache.ICache
   RefreshContainerCache cache.ICache
}

func InitLocalCaches() *LocalCaches{

	rpc := cache.NewMemCache(cache.WithClearInterval(10*time.Minute))
	rcc := cache.NewMemCache(cache.WithClearInterval(10*time.Minute))

	return &LocalCaches{
			rpc,rcc,
	}
}