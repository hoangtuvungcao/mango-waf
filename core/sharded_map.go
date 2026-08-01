package core

import (
	"sync"
	"time"
)

const numShards = 256

type ShardedTimeMap struct {
	shards [numShards]*timeMapShard
}

type timeMapShard struct {
	sync.RWMutex
	items map[string]time.Time
}

func NewShardedTimeMap() *ShardedTimeMap {
	sm := &ShardedTimeMap{}
	for i := 0; i < numShards; i++ {
		sm.shards[i] = &timeMapShard{
			items: make(map[string]time.Time, 1024),
		}
	}
	return sm
}

// fnv32a hashes a string to a shard index
func (sm *ShardedTimeMap) getShard(key string) *timeMapShard {
	var hash uint32 = 2166136261
	for i := 0; i < len(key); i++ {
		hash ^= uint32(key[i])
		hash *= 16777619
	}
	return sm.shards[hash%numShards]
}

func (sm *ShardedTimeMap) Load(key string) (time.Time, bool) {
	shard := sm.getShard(key)
	shard.RLock()
	val, ok := shard.items[key]
	shard.RUnlock()
	return val, ok
}

func (sm *ShardedTimeMap) Store(key string, value time.Time) {
	shard := sm.getShard(key)
	shard.Lock()
	shard.items[key] = value
	shard.Unlock()
}

func (sm *ShardedTimeMap) Delete(key string) {
	shard := sm.getShard(key)
	shard.Lock()
	delete(shard.items, key)
	shard.Unlock()
}

// LoadOrStore returns the existing value, or sets it and returns the new value.
// The boolean is true if it was loaded (already existed), false if stored (new).
func (sm *ShardedTimeMap) LoadOrStore(key string, value time.Time) (time.Time, bool) {
	shard := sm.getShard(key)
	shard.RLock()
	val, ok := shard.items[key]
	shard.RUnlock()
	if ok {
		return val, true
	}

	shard.Lock()
	defer shard.Unlock()
	if val, ok := shard.items[key]; ok {
		return val, true
	}
	shard.items[key] = value
	return value, false
}

// Cleanup removes expired entries and returns the number of cleaned items
func (sm *ShardedTimeMap) Cleanup(now time.Time) int {
	var count int
	for i := 0; i < numShards; i++ {
		shard := sm.shards[i]
		shard.Lock()
		for k, v := range shard.items {
			if v.Before(now) {
				delete(shard.items, k)
				count++
			}
		}
		shard.Unlock()
	}
	return count
}

// Clear completely empties the map
func (sm *ShardedTimeMap) Clear() {
	for i := 0; i < numShards; i++ {
		shard := sm.shards[i]
		shard.Lock()
		shard.items = make(map[string]time.Time, 1024)
		shard.Unlock()
	}
}

// Snapshot returns a copy of all current items
func (sm *ShardedTimeMap) Snapshot() map[string]time.Time {
	snapshot := make(map[string]time.Time)
	for i := 0; i < numShards; i++ {
		shard := sm.shards[i]
		shard.RLock()
		for k, v := range shard.items {
			snapshot[k] = v
		}
		shard.RUnlock()
	}
	return snapshot
}
