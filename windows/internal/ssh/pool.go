package ssh

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// ============================================================================
// CONNECTION POOL CONFIGURATION
// ============================================================================

// PoolConfig defines connection pool behavior
type PoolConfig struct {
	// MaxIdle is the maximum number of idle connections in the pool
	MaxIdle int

	// MaxActive is the maximum number of active connections
	// 0 means unlimited
	MaxActive int

	// IdleTimeout is the maximum time a connection can be idle before being closed
	IdleTimeout time.Duration

	// WaitTimeout is the maximum time to wait for a connection from the pool
	WaitTimeout time.Duration

	// TestOnBorrow tests connection health before returning from pool
	TestOnBorrow bool

	// TestInterval is the minimum time between connection health checks
	TestInterval time.Duration
}

// DefaultPoolConfig returns sensible defaults for connection pooling
func DefaultPoolConfig() PoolConfig {
	return PoolConfig{
		MaxIdle:      5,
		MaxActive:    10,
		IdleTimeout:  5 * time.Minute,
		WaitTimeout:  30 * time.Second,
		TestOnBorrow: true,
		TestInterval: 30 * time.Second,
	}
}

// ============================================================================
// POOLED CONNECTION
// ============================================================================

// pooledConnection wraps a Client with pool metadata
type pooledConnection struct {
	client     *Client
	lastUsed   time.Time
	lastTested time.Time
	borrowed   bool
	closeOnce  sync.Once
	pool       *ConnectionPool
	createdAt  time.Time
	useCount   int64
}

// isHealthy checks if connection is still healthy
func (pc *pooledConnection) isHealthy(ctx context.Context) bool {
	// Simple health check: execute a basic command
	_, _, err := pc.client.ExecuteCommand("hostname", 5)
	return err == nil
}

// shouldTest determines if connection should be tested
func (pc *pooledConnection) shouldTest(config PoolConfig) bool {
	if !config.TestOnBorrow {
		return false
	}
	return time.Since(pc.lastTested) > config.TestInterval
}

// close closes the underlying SSH connection
func (pc *pooledConnection) close() {
	pc.closeOnce.Do(func() {
		if pc.client != nil {
			pc.client.Close()
		}
	})
}

// ============================================================================
// CONNECTION POOL
// ============================================================================

// ConnectionPool manages a pool of SSH connections
type ConnectionPool struct {
	config     Config
	poolConfig PoolConfig

	mu            sync.RWMutex
	idle          []*pooledConnection
	active        map[*pooledConnection]struct{}
	waiting       []chan *pooledConnection
	closed        bool
	cleanupTicker *time.Ticker
	cleanupDone   chan struct{}

	// Metrics
	stats PoolStats
}

// PoolStats tracks pool performance metrics
type PoolStats struct {
	mu sync.RWMutex

	TotalConnections   int64
	ActiveConnections  int64
	IdleConnections    int64
	WaitCount          int64
	WaitDuration       time.Duration
	ConnectionsCreated int64
	ConnectionsClosed  int64
	HealthChecksFailed int64
}

// NewConnectionPool creates a new connection pool
func NewConnectionPool(config Config, poolConfig PoolConfig) *ConnectionPool {
	pool := &ConnectionPool{
		config:        config,
		poolConfig:    poolConfig,
		idle:          make([]*pooledConnection, 0, poolConfig.MaxIdle),
		active:        make(map[*pooledConnection]struct{}),
		waiting:       make([]chan *pooledConnection, 0),
		cleanupDone:   make(chan struct{}),
		cleanupTicker: time.NewTicker(30 * time.Second),
	}

	// Start cleanup goroutine
	go pool.cleanupLoop()

	return pool
}

// Get retrieves a connection from the pool or creates a new one
func (p *ConnectionPool) Get(ctx context.Context) (*Client, error) {
	p.mu.Lock()

	// Check if pool is closed
	if p.closed {
		p.mu.Unlock()
		return nil, errors.New("connection pool is closed")
	}

	// Try to get idle connection first
	for len(p.idle) > 0 {
		pc := p.idle[len(p.idle)-1]
		p.idle = p.idle[:len(p.idle)-1]

		// Test connection if needed
		if pc.shouldTest(p.poolConfig) {
			if !pc.isHealthy(ctx) {
				tflog.Debug(ctx, "Connection health check failed, discarding",
					map[string]any{"age": time.Since(pc.createdAt)})
				pc.close()
				p.stats.recordHealthCheckFailed()
				continue
			}
			pc.lastTested = time.Now()
		}

		// Mark as active and return
		pc.borrowed = true
		pc.lastUsed = time.Now()
		pc.useCount++
		p.active[pc] = struct{}{}
		p.stats.recordGet()
		p.mu.Unlock()

		tflog.Debug(ctx, "Reused connection from pool",
			map[string]any{
				"use_count": pc.useCount,
				"age":       time.Since(pc.createdAt),
			})

		return pc.client, nil
	}

	// Check if we can create a new connection
	if p.poolConfig.MaxActive > 0 && len(p.active) >= p.poolConfig.MaxActive {
		// Wait for a connection to become available
		return p.waitForConnection(ctx)
	}

	p.mu.Unlock()

	// Create new connection
	return p.createConnection(ctx)
}

// waitForConnection waits for a connection to become available
func (p *ConnectionPool) waitForConnection(ctx context.Context) (*Client, error) {
	waitChan := make(chan *pooledConnection, 1)
	p.waiting = append(p.waiting, waitChan)
	p.stats.recordWaitStart()
	p.mu.Unlock()

	startWait := time.Now()
	defer func() {
		p.stats.recordWaitEnd(time.Since(startWait))
	}()

	// Wait with timeout
	timeout := p.poolConfig.WaitTimeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	select {
	case pc := <-waitChan:
		if pc == nil {
			return nil, errors.New("pool closed while waiting for connection")
		}
		tflog.Debug(ctx, "Received connection from wait queue",
			map[string]any{"wait_duration": time.Since(startWait)})
		return pc.client, nil

	case <-time.After(timeout):
		// Remove from waiting list
		p.mu.Lock()
		p.removeWaiter(waitChan)
		p.mu.Unlock()
		return nil, fmt.Errorf("timeout waiting for connection after %v", timeout)

	case <-ctx.Done():
		p.mu.Lock()
		p.removeWaiter(waitChan)
		p.mu.Unlock()
		return nil, ctx.Err()
	}
}

// removeWaiter removes a waiter from the waiting list
func (p *ConnectionPool) removeWaiter(waitChan chan *pooledConnection) {
	for i, ch := range p.waiting {
		if ch == waitChan {
			p.waiting = append(p.waiting[:i], p.waiting[i+1:]...)
			close(waitChan)
			break
		}
	}
}

// createConnection creates a new SSH connection
func (p *ConnectionPool) createConnection(ctx context.Context) (*Client, error) {
	tflog.Debug(ctx, "Creating new SSH connection")

	client, err := NewClient(p.config)
	if err != nil {
		return nil, fmt.Errorf("failed to create SSH connection: %w", err)
	}

	pc := &pooledConnection{
		client:     client,
		lastUsed:   time.Now(),
		lastTested: time.Now(),
		borrowed:   true,
		pool:       p,
		createdAt:  time.Now(),
		useCount:   1,
	}

	p.mu.Lock()
	p.active[pc] = struct{}{}
	p.stats.recordCreate()
	p.mu.Unlock()

	tflog.Debug(ctx, "Created new SSH connection",
		map[string]any{
			"active_count": len(p.active),
			"idle_count":   len(p.idle),
		})

	return client, nil
}

// Put returns a connection to the pool
func (p *ConnectionPool) Put(client *Client) {
	if client == nil {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// Find the pooled connection
	var pc *pooledConnection
	for conn := range p.active {
		if conn.client == client {
			pc = conn
			break
		}
	}

	if pc == nil {
		// Connection not from this pool, just close it
		client.Close()
		return
	}

	// Remove from active
	delete(p.active, pc)
	pc.borrowed = false
	pc.lastUsed = time.Now()

	// Check if pool is closed
	if p.closed {
		pc.close()
		p.stats.recordClose()
		return
	}

	// Try to give to a waiter first
	if len(p.waiting) > 0 {
		waiter := p.waiting[0]
		p.waiting = p.waiting[1:]
		pc.borrowed = true
		pc.useCount++
		p.active[pc] = struct{}{}
		waiter <- pc
		close(waiter)
		return
	}

	// Add to idle pool if not full
	if len(p.idle) < p.poolConfig.MaxIdle {
		p.idle = append(p.idle, pc)
		p.stats.recordPut()
		return
	}

	// Pool is full, close the connection
	pc.close()
	p.stats.recordClose()
}

// Close closes all connections in the pool
func (p *ConnectionPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return
	}

	p.closed = true

	// Stop cleanup goroutine
	p.cleanupTicker.Stop()
	close(p.cleanupDone)

	// Notify all waiters
	for _, waiter := range p.waiting {
		waiter <- nil
		close(waiter)
	}
	p.waiting = nil

	// Close all idle connections
	for _, pc := range p.idle {
		pc.close()
		p.stats.recordClose()
	}
	p.idle = nil

	// Close all active connections
	for pc := range p.active {
		pc.close()
		p.stats.recordClose()
	}
	p.active = nil
}

// cleanupLoop periodically cleans up idle connections
func (p *ConnectionPool) cleanupLoop() {
	for {
		select {
		case <-p.cleanupTicker.C:
			p.cleanup()
		case <-p.cleanupDone:
			return
		}
	}
}

// cleanup removes idle connections that have exceeded IdleTimeout
func (p *ConnectionPool) cleanup() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return
	}

	now := time.Now()
	validIdle := make([]*pooledConnection, 0, len(p.idle))

	for _, pc := range p.idle {
		if now.Sub(pc.lastUsed) > p.poolConfig.IdleTimeout {
			// Connection has been idle too long, close it
			pc.close()
			p.stats.recordClose()
		} else {
			validIdle = append(validIdle, pc)
		}
	}

	p.idle = validIdle
}

// Stats returns current pool statistics
func (p *ConnectionPool) Stats() PoolStats {
	p.mu.RLock()
	defer p.mu.RUnlock()

	stats := p.stats
	stats.ActiveConnections = int64(len(p.active))
	stats.IdleConnections = int64(len(p.idle))
	stats.TotalConnections = stats.ActiveConnections + stats.IdleConnections

	return stats
}

// ============================================================================
// POOL STATS METHODS
// ============================================================================

func (s *PoolStats) recordGet() {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Just tracking, no increment needed as we track in real-time
}

func (s *PoolStats) recordPut() {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Just tracking, no increment needed as we track in real-time
}

func (s *PoolStats) recordCreate() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ConnectionsCreated++
}

func (s *PoolStats) recordClose() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ConnectionsClosed++
}

func (s *PoolStats) recordWaitStart() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.WaitCount++
}

func (s *PoolStats) recordWaitEnd(duration time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.WaitDuration += duration
}

func (s *PoolStats) recordHealthCheckFailed() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.HealthChecksFailed++
}

// String returns a human-readable representation of stats
func (s PoolStats) String() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	avgWait := time.Duration(0)
	if s.WaitCount > 0 {
		avgWait = s.WaitDuration / time.Duration(s.WaitCount)
	}

	return fmt.Sprintf(
		"Pool Stats: Total=%d Active=%d Idle=%d | Created=%d Closed=%d | Waits=%d AvgWait=%v | HealthChecksFailed=%d",
		s.TotalConnections,
		s.ActiveConnections,
		s.IdleConnections,
		s.ConnectionsCreated,
		s.ConnectionsClosed,
		s.WaitCount,
		avgWait,
		s.HealthChecksFailed,
	)
}
