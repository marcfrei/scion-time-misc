package sync

import (
	"sync"
)

type Context struct {
	mu sync.Mutex
}

func (c *Context) Open() {
	ok := c.mu.TryLock()
	if !ok {
		panic("sync.Context: inconsistent synchronization")
	}
}

func (c *Context) Close() {
	c.mu.Unlock()
}
