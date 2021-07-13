package common

import (
	"fmt"
	"github.com/mitchellh/hashstructure"
	"github.com/patrickmn/go-cache"
	"sync"
	"time"
)

type AppCache struct {
	Cache *cache.Cache
}

func (a *AppCache) Get(key interface{}) interface{} {
	hash, err := hashstructure.Hash(key, nil)
	if err != nil {
		return nil
	}
	value, found := a.Cache.Get(fmt.Sprintf("%d", hash))
	if !found {
		return nil
	}
	return value
}

func (a *AppCache) Set(key map[string]string, value interface{}) {
	hash, err := hashstructure.Hash(key, nil)
	if err != nil {
		return
	}
	a.Cache.Set(fmt.Sprint(hash), value, cache.DefaultExpiration)
}

func (a *AppCache) SetKey(key string, value interface{}) {
	a.Cache.Set(key, value, cache.DefaultExpiration)
}

func (a *AppCache) Del(key map[string]string) {
	hash, _ := hashstructure.Hash(key, nil)
	a.Cache.Delete(fmt.Sprint(hash))
}

func (a *AppCache) OnEvict(fn func(string, interface{})) {
	a.Cache.OnEvicted(fn)
}

func NewAppCache(arg ...time.Duration) AppCache {
	var retention time.Duration = 5
	var cleanup time.Duration = 10
	if len(arg) > 0 {
		retention = arg[0]
		if len(arg) > 1 {
			cleanup = arg[1]
		}
	}
	c := AppCache{}
	c.Cache = cache.New(retention*time.Minute, cleanup*time.Minute)
	return c
}

func NewQuickCache(arg ...time.Duration) AppCache {
	var retention time.Duration = 5
	var cleanup time.Duration = 10
	if len(arg) > 0 {
		retention = arg[0]
		if len(arg) > 1 {
			cleanup = arg[1]
		}
	}
	c := AppCache{}
	c.Cache = cache.New(retention*time.Second, cleanup*time.Second)
	return c
}

type KeyValueStore struct {
	cache map[string]interface{}
	sync.RWMutex
}

func NewKeyValueStore() KeyValueStore {
	return KeyValueStore{cache: make(map[string]interface{})}
}

func (s *KeyValueStore) Get(key string) interface{} {
	s.RLock()
	val := s.cache[key]
	s.RUnlock()
	return val
}

func (s *KeyValueStore) Set(key string, value interface{}) {
	s.Lock()
	s.cache[key] = value
	s.Unlock()
}

func (s *KeyValueStore) Clear() {
	s.Lock()
	s.cache = make(map[string]interface{})
	s.Unlock()
}
