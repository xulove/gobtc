// Copyright (c) 2015 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package peer

import (
	"bytes"
	"container/list"
	"fmt"
	"sync"
)
//mrunoncemap.go: 与mruinvmap.go类似，
// 它实现了一个缓存nonce值的LRU Cache。这里的nonce值是一个64位随机整数值，用于填充Peer间握手交换Version信息的nonce字段，
// nonce字段用来判断欲连接的Peer是否就是自己：节点发出Version消息时，会填入一个随机的nonce值，连接不同Peer节点时，节点会缓存所有为Version消息生成的nonce值；
// 如果节点收到了一个Version消息且其中的nonce值是自己缓存的nonce中的一个，那么可以判断这个Version消息由自己发送给自己了; 。
// mruNonceMap provides a concurrency safe map that is limited to a maximum
// number of items with eviction for the oldest entry when the limit is
// exceeded.
type mruNonceMap struct {
	mtx       sync.Mutex
	nonceMap  map[uint64]*list.Element // nearly O(1) lookups
	nonceList *list.List               // O(1) insert, update, delete
	limit     uint
}

// String returns the map as a human-readable string.
//
// This function is safe for concurrent access.
func (m *mruNonceMap) String() string {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	lastEntryNum := len(m.nonceMap) - 1
	curEntry := 0
	buf := bytes.NewBufferString("[")
	for nonce := range m.nonceMap {
		buf.WriteString(fmt.Sprintf("%d", nonce))
		if curEntry < lastEntryNum {
			buf.WriteString(", ")
		}
		curEntry++
	}
	buf.WriteString("]")

	return fmt.Sprintf("<%d>%s", m.limit, buf.String())
}

// Exists returns whether or not the passed nonce is in the map.
//
// This function is safe for concurrent access.
func (m *mruNonceMap) Exists(nonce uint64) bool {
	m.mtx.Lock()
	_, exists := m.nonceMap[nonce]
	m.mtx.Unlock()

	return exists
}

// Add adds the passed nonce to the map and handles eviction of the oldest item
// if adding the new item would exceed the max limit.  Adding an existing item
// makes it the most recently used item.
//
// This function is safe for concurrent access.
func (m *mruNonceMap) Add(nonce uint64) {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	// When the limit is zero, nothing can be added to the map, so just
	// return.
	if m.limit == 0 {
		return
	}

	// When the entry already exists move it to the front of the list
	// thereby marking it most recently used.
	if node, exists := m.nonceMap[nonce]; exists {
		m.nonceList.MoveToFront(node)
		return
	}

	// Evict the least recently used entry (back of the list) if the the new
	// entry would exceed the size limit for the map.  Also reuse the list
	// node so a new one doesn't have to be allocated.
	if uint(len(m.nonceMap))+1 > m.limit {
		node := m.nonceList.Back()
		lru := node.Value.(uint64)

		// Evict least recently used item.
		delete(m.nonceMap, lru)

		// Reuse the list node of the item that was just evicted for the
		// new item.
		node.Value = nonce
		m.nonceList.MoveToFront(node)
		m.nonceMap[nonce] = node
		return
	}

	// The limit hasn't been reached yet, so just add the new item.
	node := m.nonceList.PushFront(nonce)
	m.nonceMap[nonce] = node
}

// Delete deletes the passed nonce from the map (if it exists).
//
// This function is safe for concurrent access.
func (m *mruNonceMap) Delete(nonce uint64) {
	m.mtx.Lock()
	if node, exists := m.nonceMap[nonce]; exists {
		m.nonceList.Remove(node)
		delete(m.nonceMap, nonce)
	}
	m.mtx.Unlock()
}

// newMruNonceMap returns a new nonce map that is limited to the number of
// entries specified by limit.  When the number of entries exceeds the limit,
// the oldest (least recently used) entry will be removed to make room for the
// new entry.
func newMruNonceMap(limit uint) *mruNonceMap {
	m := mruNonceMap{
		nonceMap:  make(map[uint64]*list.Element),
		nonceList: list.New(),
		limit:     limit,
	}
	return &m
}
