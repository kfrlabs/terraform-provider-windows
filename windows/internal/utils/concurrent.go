package utils

import (
	"context"
	"fmt"
	"sync"
)

// ============================================================================
// CONCURRENT OPERATION HELPERS
// ============================================================================

// WorkerPool manages concurrent operations with a limited number of workers
type WorkerPool struct {
	workerCount int
	jobs        chan func() error
	results     chan error
	wg          sync.WaitGroup
	ctx         context.Context
	cancel      context.CancelFunc
}

// NewWorkerPool creates a new worker pool with the specified number of workers
func NewWorkerPool(ctx context.Context, workerCount int) *WorkerPool {
	poolCtx, cancel := context.WithCancel(ctx)

	return &WorkerPool{
		workerCount: workerCount,
		jobs:        make(chan func() error, workerCount*2),
		results:     make(chan error, workerCount*2),
		ctx:         poolCtx,
		cancel:      cancel,
	}
}

// Start starts the worker pool
func (wp *WorkerPool) Start() {
	for i := 0; i < wp.workerCount; i++ {
		wp.wg.Add(1)
		go wp.worker()
	}
}

// worker processes jobs from the jobs channel
func (wp *WorkerPool) worker() {
	defer wp.wg.Done()

	for {
		select {
		case job, ok := <-wp.jobs:
			if !ok {
				return
			}
			wp.results <- job()

		case <-wp.ctx.Done():
			return
		}
	}
}

// Submit submits a job to the worker pool
func (wp *WorkerPool) Submit(job func() error) {
	select {
	case wp.jobs <- job:
	case <-wp.ctx.Done():
	}
}

// Wait waits for all jobs to complete and returns any errors
func (wp *WorkerPool) Wait() []error {
	close(wp.jobs)
	wp.wg.Wait()
	close(wp.results)

	var errors []error
	for err := range wp.results {
		if err != nil {
			errors = append(errors, err)
		}
	}

	return errors
}

// Close closes the worker pool
func (wp *WorkerPool) Close() {
	wp.cancel()
	close(wp.jobs)
	wp.wg.Wait()
	close(wp.results)
}

// ============================================================================
// BATCH OPERATION HELPERS
// ============================================================================

// BatchOperation represents a single operation in a batch
type BatchOperation struct {
	Name      string
	Operation func() error
}

// ExecuteBatch executes multiple operations concurrently with a worker pool
func ExecuteBatch(ctx context.Context, operations []BatchOperation, maxConcurrency int) error {
	if len(operations) == 0 {
		return nil
	}

	// Use worker pool for concurrent execution
	pool := NewWorkerPool(ctx, maxConcurrency)
	pool.Start()

	// Submit all operations
	for _, op := range operations {
		op := op // Capture loop variable
		pool.Submit(func() error {
			if err := op.Operation(); err != nil {
				return fmt.Errorf("operation '%s' failed: %w", op.Name, err)
			}
			return nil
		})
	}

	// Wait for completion
	errors := pool.Wait()

	if len(errors) > 0 {
		return fmt.Errorf("batch execution failed with %d errors: %v", len(errors), errors[0])
	}

	return nil
}

// ============================================================================
// PARALLEL MAP OPERATION
// ============================================================================

// ParallelMap applies a function to each item in a slice concurrently
func ParallelMap[T any, R any](
	ctx context.Context,
	items []T,
	fn func(T) (R, error),
	maxConcurrency int,
) ([]R, []error) {
	if len(items) == 0 {
		return []R{}, []error{}
	}

	results := make([]R, len(items))
	errors := make([]error, len(items))

	pool := NewWorkerPool(ctx, maxConcurrency)
	pool.Start()

	var mu sync.Mutex

	for i, item := range items {
		i, item := i, item // Capture loop variables
		pool.Submit(func() error {
			result, err := fn(item)

			mu.Lock()
			results[i] = result
			errors[i] = err
			mu.Unlock()

			return err
		})
	}

	pool.Wait()

	// Filter out nil errors
	var actualErrors []error
	for _, err := range errors {
		if err != nil {
			actualErrors = append(actualErrors, err)
		}
	}

	return results, actualErrors
}

// ============================================================================
// RESULT AGGREGATOR
// ============================================================================

// ResultAggregator collects results from concurrent operations
type ResultAggregator[T any] struct {
	mu      sync.Mutex
	results []T
	errors  []error
}

// NewResultAggregator creates a new result aggregator
func NewResultAggregator[T any]() *ResultAggregator[T] {
	return &ResultAggregator[T]{
		results: make([]T, 0),
		errors:  make([]error, 0),
	}
}

// Add adds a result to the aggregator
func (ra *ResultAggregator[T]) Add(result T, err error) {
	ra.mu.Lock()
	defer ra.mu.Unlock()

	if err != nil {
		ra.errors = append(ra.errors, err)
	} else {
		ra.results = append(ra.results, result)
	}
}

// Results returns all successful results
func (ra *ResultAggregator[T]) Results() []T {
	ra.mu.Lock()
	defer ra.mu.Unlock()
	return ra.results
}

// Errors returns all errors
func (ra *ResultAggregator[T]) Errors() []error {
	ra.mu.Lock()
	defer ra.mu.Unlock()
	return ra.errors
}

// HasErrors checks if any errors occurred
func (ra *ResultAggregator[T]) HasErrors() bool {
	ra.mu.Lock()
	defer ra.mu.Unlock()
	return len(ra.errors) > 0
}

// Count returns the number of successful results
func (ra *ResultAggregator[T]) Count() int {
	ra.mu.Lock()
	defer ra.mu.Unlock()
	return len(ra.results)
}
