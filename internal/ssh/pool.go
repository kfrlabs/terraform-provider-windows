package ssh

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// PoolConfig holds the configuration for the connection pool
type PoolConfig struct {
	// MaxIdle is the maximum number of idle connections in the pool
	MaxIdle int

	// MaxActive is the maximum number of active connections (0 = unlimited)
	MaxActive int

	// IdleTimeout is the maximum time a connection can be idle before being closed
	IdleTimeout time.Duration

	// WaitTimeout is the maximum time to wait for a connection from the pool
	WaitTimeout time.Duration

	// TestOnBorrow tests the connection health when borrowing from pool
	TestOnBorrow bool

	// TestInterval is the minimum time between health checks
	TestInterval time.Duration
}

// PoolStats contains statistics about the connection pool
type PoolStats struct {
	// ActiveCount is the number of connections currently in use
	ActiveCount int

	// IdleCount is the number of idle connections available
	IdleCount int

	// WaitCount is the number of requests waiting for a connection
	WaitCount int

	// WaitDuration is the total time spent waiting for connections
	WaitDuration time.Duration

	// MaxActive is the configured maximum number of active connections
	MaxActive int

	// MaxIdle is the configured maximum number of idle connections
	MaxIdle int

	// TotalCreated is the total number of connections created
	TotalCreated int

	// TotalClosed is the total number of connections closed
	TotalClosed int
}

// pooledClient wraps a Client with pool-specific metadata
type pooledClient struct {
	client       *Client
	borrowed     bool
	lastBorrowed time.Time
	lastReturned time.Time
	lastHealthCheck time.Time
	borrowCount  int
}

// ConnectionPool manages a pool of SSH client connections
type ConnectionPool struct {
	config     Config
	poolConfig PoolConfig

	mu            sync.Mutex
	idleClients   []*pooledClient
	activeClients map[*Client]*pooledClient
	waitQueue     []chan *pooledClient

	stats struct {
		totalCreated int
		totalClosed  int
		totalWaitTime time.Duration
	}

	closed bool
}

// NewConnectionPool creates a new connection pool with the given configuration
func NewConnectionPool(config Config, poolConfig PoolConfig) *ConnectionPool {
	// Set defaults
	if poolConfig.MaxIdle == 0 {
		poolConfig.MaxIdle = 5
	}
	if poolConfig.MaxActive == 0 {
		poolConfig.MaxActive = 10
	}
	if poolConfig.IdleTimeout == 0 {
		poolConfig.IdleTimeout = 300 * time.Second // 5 minutes
	}
	if poolConfig.WaitTimeout == 0 {
		poolConfig.WaitTimeout = 30 * time.Second
	}
	if poolConfig.TestInterval == 0 {
		poolConfig.TestInterval = 30 * time.Second
	}

	pool := &ConnectionPool{
		config:        config,
		poolConfig:    poolConfig,
		idleClients:   make([]*pooledClient, 0, poolConfig.MaxIdle),
		activeClients: make(map[*Client]*pooledClient),
		waitQueue:     make([]chan *pooledClient, 0),
	}

	// Start background maintenance goroutine
	go pool.maintenanceLoop()

	return pool
}

// Get retrieves a client from the pool or creates a new one.
// The caller must call Put() to return the client to the pool when done.
func (p *ConnectionPool) Get(ctx context.Context) (*Client, error) {
	p.mu.Lock()

	if p.closed {
		p.mu.Unlock()
		return nil, fmt.Errorf("connection pool is closed")
	}

	// Try to get an idle client
	for len(p.idleClients) > 0 {
		// Get client from the end (LIFO - most recently used)
		pc := p.idleClients[len(p.idleClients)-1]
		p.idleClients = p.idleClients[:len(p.idleClients)-1]

		// Check if client is still healthy if configured
		if p.poolConfig.TestOnBorrow {
			if time.Since(pc.lastHealthCheck) > p.poolConfig.TestInterval {
				healthy := pc.client.IsHealthy(ctx)
				pc.lastHealthCheck = time.Now()
				
				if !healthy {
					// Client is unhealthy, close it and try next
					p.mu.Unlock()
					pc.client.Close()
					p.mu.Lock()
					p.stats.totalClosed++
					continue
				}
			}
		}

		// Mark as borrowed and track it
		pc.borrowed = true
		pc.lastBorrowed = time.Now()
		pc.borrowCount++
		p.activeClients[pc.client] = pc

		p.mu.Unlock()
		return pc.client, nil
	}

	// No idle clients available, check if we can create a new one
	activeCount := len(p.activeClients)
	canCreate := p.poolConfig.MaxActive == 0 || activeCount < p.poolConfig.MaxActive

	if canCreate {
		// Create new client
		p.mu.Unlock()

		client, err := NewClient(p.config)
		if err != nil {
			return nil, fmt.Errorf("failed to create new client: %w", err)
		}

		p.mu.Lock()
		pc := &pooledClient{
			client:       client,
			borrowed:     true,
			lastBorrowed: time.Now(),
			lastHealthCheck: time.Now(),
			borrowCount:  1,
		}
		p.activeClients[client] = pc
		p.stats.totalCreated++
		p.mu.Unlock()

		return client, nil
	}

	// Pool is at max capacity, wait for a client to be returned
	waitChan := make(chan *pooledClient, 1)
	p.waitQueue = append(p.waitQueue, waitChan)
	p.mu.Unlock()

	// Wait with timeout
	waitStart := time.Now()
	select {
	case pc := <-waitChan:
		p.mu.Lock()
		p.stats.totalWaitTime += time.Since(waitStart)
		p.mu.Unlock()
		return pc.client, nil

	case <-ctx.Done():
		// Remove from wait queue
		p.mu.Lock()
		p.removeFromWaitQueue(waitChan)
		p.mu.Unlock()
		return nil, fmt.Errorf("context cancelled while waiting for connection: %w", ctx.Err())

	case <-time.After(p.poolConfig.WaitTimeout):
		// Remove from wait queue
		p.mu.Lock()
		p.removeFromWaitQueue(waitChan)
		p.mu.Unlock()
		return nil, fmt.Errorf("timeout waiting for connection after %v", p.poolConfig.WaitTimeout)
	}
}

// Put returns a client to the pool
func (p *ConnectionPool) Put(client *Client) {
	if client == nil {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		// Pool is closed, close the client
		client.Close()
		return
	}

	// Get pooled client metadata
	pc, exists := p.activeClients[client]
	if !exists {
		// Client not from this pool, close it
		client.Close()
		return
	}

	// Remove from active clients
	delete(p.activeClients, client)
	pc.borrowed = false
	pc.lastReturned = time.Now()

	// Check if there are waiters
	if len(p.waitQueue) > 0 {
		// Give to first waiter
		waiter := p.waitQueue[0]
		p.waitQueue = p.waitQueue[1:]
		
		pc.borrowed = true
		pc.lastBorrowed = time.Now()
		pc.borrowCount++
		p.activeClients[client] = pc
		
		waiter <- pc
		return
	}

	// Check if we should keep this connection idle
	if len(p.idleClients) < p.poolConfig.MaxIdle {
		// Add to idle pool
		p.idleClients = append(p.idleClients, pc)
	} else {
		// Pool is full, close the connection
		client.Close()
		p.stats.totalClosed++
	}
}

// removeFromWaitQueue removes a channel from the wait queue
func (p *ConnectionPool) removeFromWaitQueue(ch chan *pooledClient) {
	for i, waiter := range p.waitQueue {
		if waiter == ch {
			p.waitQueue = append(p.waitQueue[:i], p.waitQueue[i+1:]...)
			break
		}
	}
}

// maintenanceLoop runs periodic maintenance tasks on the pool
func (p *ConnectionPool) maintenanceLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return
		}

		// Close idle connections that have exceeded idle timeout
		newIdleClients := make([]*pooledClient, 0, len(p.idleClients))
		for _, pc := range p.idleClients {
			if time.Since(pc.lastReturned) > p.poolConfig.IdleTimeout {
				// Close expired idle connection
				pc.client.Close()
				p.stats.totalClosed++
			} else {
				newIdleClients = append(newIdleClients, pc)
			}
		}
		p.idleClients = newIdleClients

		p.mu.Unlock()
	}
}

// Stats returns current statistics about the connection pool
func (p *ConnectionPool) Stats() PoolStats {
	p.mu.Lock()
	defer p.mu.Unlock()

	return PoolStats{
		ActiveCount:  len(p.activeClients),
		IdleCount:    len(p.idleClients),
		WaitCount:    len(p.waitQueue),
		WaitDuration: p.stats.totalWaitTime,
		MaxActive:    p.poolConfig.MaxActive,
		MaxIdle:      p.poolConfig.MaxIdle,
		TotalCreated: p.stats.totalCreated,
		TotalClosed:  p.stats.totalClosed,
	}
}

// Close closes all connections in the pool and prevents new ones from being created
func (p *ConnectionPool) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return nil
	}

	p.closed = true

	// Close all idle connections
	for _, pc := range p.idleClients {
		pc.client.Close()
	}
	p.idleClients = nil

	// Close all active connections (this might interrupt operations)
	for client, _ := range p.activeClients {
		client.Close()
	}
	p.activeClients = nil

	// Notify all waiters that pool is closed
	for _, waiter := range p.waitQueue {
		close(waiter)
	}
	p.waitQueue = nil

	return nil
}

// GetConfig returns the SSH configuration used by this pool
func (p *ConnectionPool) GetConfig() Config {
	return p.config
}

// GetPoolConfig returns the pool configuration
func (p *ConnectionPool) GetPoolConfig() PoolConfig {
	return p.poolConfig
}
