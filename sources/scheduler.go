package sources

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/logging"
)

// ErrMemoryBudget is returned when a target cannot be dispatched because the
// memory budget has been (or would be) exhausted.
var ErrMemoryBudget = errors.New("memory budget exhausted")

type schedulerTargetKey struct{}

// Target tracks the accounted occupancy of a single dispatched target. It is
// passed through the work context and used to report memory growth while the
// target is processed — for example the expansion caused by decoding.
type Target struct {
	s        *Scheduler
	reserved int64 // guarded by s.mu
}

// Grow adjusts the target's accounted memory by delta. A positive delta means
// the target occupies more memory than the dispatch-time estimate; a negative
// delta means it occupies less.
func (t *Target) Grow(delta int64) {
	if t == nil || t.s == nil || delta == 0 {
		return
	}
	t.s.mu.Lock()
	t.s.memUsed += delta
	t.reserved += delta
	if t.s.memoryBytes > 0 && t.s.memUsed > t.s.memoryBytes {
		// Sticky: once the budget is exceeded no further targets are
		// dispatched for the remainder of the scan.
		t.s.memoryExhausted.Store(true)
	}
	t.s.mu.Unlock()
}

// Scheduler controls target dispatch:
//   - a worker semaphore bounds how many targets are processed at once;
//   - an in-flight semaphore bounds dispatched-but-unfinished targets;
//   - a memory budget, estimated from in-flight target occupancy (including
//     decoding growth), gates the admission of new targets.
type Scheduler struct {
	workers     chan struct{}
	inFlight    chan struct{}
	memoryBytes int64

	mu      sync.Mutex
	memUsed int64

	memoryExhausted atomic.Bool

	active sync.WaitGroup

	dispatched atomic.Int64
	skipped    atomic.Int64
}

// NewScheduler creates a Scheduler. Non-positive workers or maxInFlight
// values fall back to the defaults (workers: config.DefaultWorkers,
// maxInFlight: workers), which keeps detectors built from hand-made configs
// working and preserves the historical behavior.
func NewScheduler(workers, maxInFlight int, memoryBytes int64) *Scheduler {
	if workers <= 0 {
		workers = config.DefaultWorkers
	}
	if maxInFlight <= 0 {
		maxInFlight = workers
	}
	if memoryBytes < 0 {
		memoryBytes = 0
	}
	return &Scheduler{
		workers:     make(chan struct{}, workers),
		inFlight:    make(chan struct{}, maxInFlight),
		memoryBytes: memoryBytes,
	}
}

// Go dispatches f as a new target identified by |id| with an estimated size
// of |estSize| bytes. It blocks while the in-flight or worker limits are
// reached.
//
// If the target cannot be dispatched because the memory budget has been (or
// would be) exhausted, the target is logged — with its identifier and the
// reason — and ErrMemoryBudget is returned.
//
// Cancellation of |parent| propagates to a blocking dispatch and to the work
// function, which receives a derived context.
func (s *Scheduler) Go(parent context.Context, id string, estSize int64, f func(ctx context.Context) error) error {
	if s.memoryExhausted.Load() {
		return s.skip(id, estSize)
	}

	// Bound dispatched-but-unfinished targets.
	select {
	case s.inFlight <- struct{}{}:
	case <-parent.Done():
		return parent.Err()
	}

	t := &Target{s: s}

	s.mu.Lock()
	if s.memoryExhausted.Load() || (s.memoryBytes > 0 && s.memUsed+estSize > s.memoryBytes) {
		s.memoryExhausted.Store(true)
		s.mu.Unlock()
		<-s.inFlight
		return s.skip(id, estSize)
	}
	s.memUsed += estSize
	t.reserved = estSize
	s.mu.Unlock()

	// Bound simultaneous processing. Block here (with the target admitted,
	// hence counted as in-flight) until a worker slot is available.
	select {
	case s.workers <- struct{}{}:
	case <-parent.Done():
		s.release(t)
		<-s.inFlight
		return parent.Err()
	}

	s.dispatched.Add(1)
	s.active.Add(1)
	taskCtx := context.WithValue(parent, schedulerTargetKey{}, t)
	go func() {
		defer s.active.Done()
		defer func() {
			<-s.workers
			s.release(t)
			<-s.inFlight
		}()
		// Work results are not affected by the budget; running targets always
		// run to completion.
		_ = f(taskCtx)
	}()
	return nil
}

// release frees the occupancy reserved by a finished target.
func (s *Scheduler) release(t *Target) {
	s.mu.Lock()
	s.memUsed -= t.reserved
	s.mu.Unlock()
}

// skip records and logs a target that is not dispatched due to the memory
// budget.
func (s *Scheduler) skip(id string, estSize int64) error {
	s.skipped.Add(1)
	logging.Warn().
		Str("target", id).
		Int64("est-size", estSize).
		Int64("memory-budget", s.memoryBytes).
		Msg("skipping target: memory budget exhausted")
	return ErrMemoryBudget
}

// Wait blocks until all dispatched targets have finished.
func (s *Scheduler) Wait() {
	s.active.Wait()
}

// MemoryExhausted reports whether the memory budget has been exceeded.
func (s *Scheduler) MemoryExhausted() bool {
	return s.memoryExhausted.Load()
}

// Dispatched returns the number of targets dispatched since the scheduler
// was created.
func (s *Scheduler) Dispatched() int64 {
	return s.dispatched.Load()
}

// Skipped returns the number of targets that were not dispatched due to the
// memory budget.
func (s *Scheduler) Skipped() int64 {
	return s.skipped.Load()
}

// TargetFromContext returns the Target associated with the work context, or
// nil if the context does not belong to a dispatched target.
func TargetFromContext(ctx context.Context) *Target {
	t, _ := ctx.Value(schedulerTargetKey{}).(*Target)
	return t
}
