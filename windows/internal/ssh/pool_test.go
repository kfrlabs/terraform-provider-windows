package ssh

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestDefaultPoolConfig(t *testing.T) {
	config := DefaultPoolConfig()

	if config.MaxIdle != 5 {
		t.Errorf("Expected MaxIdle=5, got %d", config.MaxIdle)
	}

	if config.MaxActive != 10 {
		t.Errorf("Expected MaxActive=10, got %d", config.MaxActive)
	}

	if config.IdleTimeout != 5*time.Minute {
		t.Errorf("Expected IdleTimeout=5m, got %v", config.IdleTimeout)
	}

	if !config.TestOnBorrow {
		t.Error("Expected TestOnBorrow=true")
	}
}

func TestPooledConnectionHealthCheck(t *testing.T) {
	// Note: This test would require a real SSH connection
	// In practice, you'd mock this
	t.Skip("Requires real SSH connection for testing")

	pc := &pooledConnection{
		lastTested: time.Now().Add(-1 * time.Minute),
	}

	config := DefaultPoolConfig()

	if !pc.shouldTest(config) {
		t.Error("Connection should be tested after 1 minute")
	}

	pc.lastTested = time.Now()
	if pc.shouldTest(config) {
		t.Error("Connection should not be tested immediately after last test")
	}
}

func TestConnectionPoolBasicOperations(t *testing.T) {
	// Note: This would require a mock SSH server for proper testing
	t.Skip("Requires mock SSH server")

	config := Config{
		Host:        "localhost",
		Username:    "test",
		Password:    "test",
		ConnTimeout: 10 * time.Second,
	}

	poolConfig := PoolConfig{
		MaxIdle:      2,
		MaxActive:    5,
		IdleTimeout:  1 * time.Minute,
		WaitTimeout:  5 * time.Second,
		TestOnBorrow: false,
	}

	pool := NewConnectionPool(config, poolConfig)
	defer pool.Close()

	ctx := context.Background()

	// Get a connection
	client, err := pool.Get(ctx)
	if err != nil {
		t.Fatalf("Failed to get connection: %v", err)
	}

	// Return it
	pool.Put(client)

	// Check stats
	stats := pool.Stats()
	if stats.ConnectionsCreated != 1 {
		t.Errorf("Expected 1 connection created, got %d", stats.ConnectionsCreated)
	}
}

func TestConnectionPoolConcurrency(t *testing.T) {
	t.Skip("Requires mock SSH server")

	config := Config{
		Host:        "localhost",
		Username:    "test",
		Password:    "test",
		ConnTimeout: 10 * time.Second,
	}

	poolConfig := PoolConfig{
		MaxIdle:      5,
		MaxActive:    10,
		IdleTimeout:  1 * time.Minute,
		WaitTimeout:  5 * time.Second,
		TestOnBorrow: false,
	}

	pool := NewConnectionPool(config, poolConfig)
	defer pool.Close()

	ctx := context.Background()
	var wg sync.WaitGroup

	// Simulate 20 concurrent requests
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			client, err := pool.Get(ctx)
			if err != nil {
				t.Errorf("Worker %d: Failed to get connection: %v", id, err)
				return
			}

			// Simulate work
			time.Sleep(10 * time.Millisecond)

			pool.Put(client)
		}(i)
	}

	wg.Wait()

	// Check final stats
	stats := pool.Stats()
	t.Logf("Final stats: %s", stats.String())

	if stats.ConnectionsCreated > 10 {
		t.Errorf("Expected max 10 connections created, got %d", stats.ConnectionsCreated)
	}
}

func TestConnectionPoolTimeout(t *testing.T) {
	t.Skip("Requires mock SSH server")

	config := Config{
		Host:        "localhost",
		Username:    "test",
		Password:    "test",
		ConnTimeout: 10 * time.Second,
	}

	poolConfig := PoolConfig{
		MaxIdle:     1,
		MaxActive:   1,
		WaitTimeout: 100 * time.Millisecond,
	}

	pool := NewConnectionPool(config, poolConfig)
	defer pool.Close()

	ctx := context.Background()

	// Get the only available connection
	client1, err := pool.Get(ctx)
	if err != nil {
		t.Fatalf("Failed to get first connection: %v", err)
	}

	// Try to get another connection - should timeout
	start := time.Now()
	_, err = pool.Get(ctx)
	elapsed := time.Since(start)

	if err == nil {
		t.Error("Expected timeout error, got nil")
	}

	if elapsed < 100*time.Millisecond {
		t.Errorf("Timeout happened too quickly: %v", elapsed)
	}

	// Return first connection
	pool.Put(client1)
}

func TestConnectionPoolCleanup(t *testing.T) {
	t.Skip("Requires mock SSH server")

	config := Config{
		Host:        "localhost",
		Username:    "test",
		Password:    "test",
		ConnTimeout: 10 * time.Second,
	}

	poolConfig := PoolConfig{
		MaxIdle:     5,
		MaxActive:   10,
		IdleTimeout: 100 * time.Millisecond,
	}

	pool := NewConnectionPool(config, poolConfig)
	defer pool.Close()

	ctx := context.Background()

	// Create and return 5 connections
	clients := make([]*Client, 5)
	for i := 0; i < 5; i++ {
		client, err := pool.Get(ctx)
		if err != nil {
			t.Fatalf("Failed to get connection %d: %v", i, err)
		}
		clients[i] = client
	}

	for _, client := range clients {
		pool.Put(client)
	}

	// Wait for cleanup to happen
	time.Sleep(200 * time.Millisecond)

	stats := pool.Stats()
	if stats.IdleConnections > 0 {
		t.Errorf("Expected 0 idle connections after cleanup, got %d", stats.IdleConnections)
	}
}

func TestPoolStats(t *testing.T) {
	stats := &PoolStats{}

	stats.recordCreate()
	stats.recordCreate()
	stats.recordClose()

	if stats.ConnectionsCreated != 2 {
		t.Errorf("Expected 2 connections created, got %d", stats.ConnectionsCreated)
	}

	if stats.ConnectionsClosed != 1 {
		t.Errorf("Expected 1 connection closed, got %d", stats.ConnectionsClosed)
	}

	stats.recordWaitStart()
	stats.recordWaitEnd(100 * time.Millisecond)

	if stats.WaitCount != 1 {
		t.Errorf("Expected 1 wait, got %d", stats.WaitCount)
	}

	statsStr := stats.String()
	if statsStr == "" {
		t.Error("Expected non-empty stats string")
	}
}
