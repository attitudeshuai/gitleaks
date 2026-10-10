package sources

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// concurrentRunner tracks how many tasks run simultaneously and how many run
// in total.
type concurrentRunner struct {
	current atomic.Int64
	max     atomic.Int64
	total   atomic.Int64
}

func (r *concurrentRunner) run(ctx context.Context) error {
	cur := r.current.Add(1)
	for {
		seen := r.max.Load()
		if cur <= seen || r.max.CompareAndSwap(seen, cur) {
			break
		}
	}
	r.total.Add(1)

	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Millisecond):
	}

	r.current.Add(-1)
	return nil
}

func TestSchedulerWorkersLimit(t *testing.T) {
	for _, workers := range []int{1, 2, 4} {
		t.Run("", func(t *testing.T) {
			s := NewScheduler(workers, workers, 0)
			r := &concurrentRunner{}

			const targetCount = 20
			for i := 0; i < targetCount; i++ {
				require.NoError(t, s.Go(context.Background(), "target", 0, r.run))
			}
			s.Wait()

			assert.Equal(t, int64(targetCount), r.total.Load(), "every target runs exactly once")
			assert.Equal(t, int64(workers), r.max.Load(), "simultaneous targets bounded by workers")
		})
	}
}

func TestSchedulerSerial(t *testing.T) {
	// workers=1 must still complete the scan correctly, just serially.
	s := NewScheduler(1, 1, 0)
	var order []int
	var mu sync.Mutex

	for i := 0; i < 10; i++ {
		i := i
		require.NoError(t, s.Go(context.Background(), "target", 0, func(context.Context) error {
			mu.Lock()
			order = append(order, i)
			mu.Unlock()
			return nil
		}))
	}
	s.Wait()

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, order)
}

func TestSchedulerInFlightLimit(t *testing.T) {
	s := NewScheduler(4, 1, 0) // plenty of workers, single in-flight slot

	var admitted atomic.Int64
	release := make(chan struct{})
	started := make(chan struct{}, 1)

	go func() {
		_ = s.Go(context.Background(), "a", 0, func(context.Context) error {
			admitted.Add(1)
			started <- struct{}{}
			<-release
			return nil
		})
	}()

	<-started
	require.Equal(t, int64(1), admitted.Load())

	secondStarted := make(chan struct{})
	go func() {
		_ = s.Go(context.Background(), "b", 0, func(context.Context) error {
			admitted.Add(1)
			close(secondStarted)
			return nil
		})
	}()

	// The second target must not be admitted while the first is in flight.
	select {
	case <-secondStarted:
		t.Fatal("second target admitted before the in-flight slot was released")
	case <-time.After(50 * time.Millisecond):
	}
	require.Equal(t, int64(1), admitted.Load())

	close(release)
	<-secondStarted
	s.Wait()
	assert.Equal(t, int64(2), admitted.Load())
}

func TestSchedulerMemoryBudget(t *testing.T) {
	const budget = int64(100)
	s := NewScheduler(4, 4, budget)

	release := make(chan struct{})
	aStarted := make(chan struct{})

	go func() {
		_ = s.Go(context.Background(), "a", 60, func(context.Context) error {
			close(aStarted)
			<-release
			return nil
		})
	}()
	<-aStarted

	// b would exceed the budget while a is in flight: not dispatched,
	// signaled and counted.
	err := s.Go(context.Background(), "b", 50, func(context.Context) error {
		t.Fatal("b should not run")
		return nil
	})
	require.ErrorIs(t, err, ErrMemoryBudget)
	assert.Equal(t, int64(1), s.Skipped())

	// Sticky: even a target that would fit after a finishes is rejected.
	err = s.Go(context.Background(), "c", 10, func(context.Context) error {
		t.Fatal("c should not run")
		return nil
	})
	require.ErrorIs(t, err, ErrMemoryBudget)
	assert.Equal(t, int64(2), s.Skipped())

	close(release)
	s.Wait()
	assert.Equal(t, int64(1), s.Dispatched(),
		"admitted targets are not affected by the budget")
	assert.True(t, s.MemoryExhausted())

	// Occupancy of finished targets is released.
	s.mu.Lock()
	assert.Equal(t, int64(0), s.memUsed)
	s.mu.Unlock()
}

func TestSchedulerExactFitAdmitted(t *testing.T) {
	s := NewScheduler(1, 1, 100)

	var ran atomic.Bool
	require.NoError(t, s.Go(context.Background(), "exact", 100, func(context.Context) error {
		ran.Store(true)
		return nil
	}))
	s.Wait()
	assert.True(t, ran.Load())
	assert.False(t, s.MemoryExhausted(), "equal to budget is not over budget")
}

func TestSchedulerGrow(t *testing.T) {
	t.Run("growth crosses budget", func(t *testing.T) {
		s := NewScheduler(1, 1, 100)
		require.NoError(t, s.Go(context.Background(), "g", 10, func(ctx context.Context) error {
			target := TargetFromContext(ctx)
			require.NotNil(t, target)
			target.Grow(90) // used == 100, still within budget
			target.Grow(1)  // used == 101, over budget
			return nil
		}))
		s.Wait()
		assert.True(t, s.MemoryExhausted())
	})

	t.Run("shrinkage releases occupancy", func(t *testing.T) {
		s := NewScheduler(1, 1, 100)
		require.NoError(t, s.Go(context.Background(), "g", 100, func(ctx context.Context) error {
			TargetFromContext(ctx).Grow(-50)
			return nil
		}))
		s.Wait()
		assert.False(t, s.MemoryExhausted())
		s.mu.Lock()
		assert.Equal(t, int64(0), s.memUsed)
		s.mu.Unlock()
	})
}

func TestSchedulerCancellation(t *testing.T) {
	t.Run("already canceled", func(t *testing.T) {
		s := NewScheduler(2, 2, 0)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		err := s.Go(ctx, "canceled", 0, func(context.Context) error {
			t.Fatal("should not run")
			return nil
		})
		require.ErrorIs(t, err, context.Canceled)

		// The canceled dispatch must not leak slots.
		var ran atomic.Bool
		require.NoError(t, s.Go(context.Background(), "after", 0, func(context.Context) error {
			ran.Store(true)
			return nil
		}))
		s.Wait()
		assert.True(t, ran.Load())
	})

	t.Run("cancel while blocked for a slot", func(t *testing.T) {
		s := NewScheduler(1, 1, 0)
		release := make(chan struct{})
		started := make(chan struct{})

		go func() {
			_ = s.Go(context.Background(), "holder", 0, func(context.Context) error {
				close(started)
				<-release
				return nil
			})
		}()
		<-started

		ctx, cancel := context.WithCancel(context.Background())
		errCh := make(chan error, 1)
		go func() {
			errCh <- s.Go(ctx, "waiting", 0, func(context.Context) error { return nil })
		}()

		cancel()
		select {
		case err := <-errCh:
			require.ErrorIs(t, err, context.Canceled)
		case <-time.After(time.Second):
			t.Fatal("blocked dispatch was not unblocked by cancellation")
		}

		close(release)
		s.Wait()
	})

	t.Run("cancel propagates into running work", func(t *testing.T) {
		s := NewScheduler(1, 1, 0)
		ctx, cancel := context.WithCancel(context.Background())

		gotCancel := make(chan struct{})
		require.NoError(t, s.Go(ctx, "work", 0, func(workCtx context.Context) error {
			cancel()
			<-workCtx.Done()
			close(gotCancel)
			return workCtx.Err()
		}))

		select {
		case <-gotCancel:
		case <-time.After(time.Second):
			t.Fatal("cancellation did not reach the running work unit")
		}
		s.Wait()
	})
}

func TestSchedulerNoDuplicateProcessing(t *testing.T) {
	s := NewScheduler(4, 4, 0)
	seen := make(map[int]struct{})
	var mu sync.Mutex

	for i := 0; i < 30; i++ {
		i := i
		require.NoError(t, s.Go(context.Background(), "target", 0, func(context.Context) error {
			mu.Lock()
			if _, ok := seen[i]; ok {
				t.Errorf("target %d processed more than once", i)
			}
			seen[i] = struct{}{}
			mu.Unlock()
			return nil
		}))
	}
	s.Wait()

	assert.Len(t, seen, 30)
}

func TestSchedulerDefaults(t *testing.T) {
	s := NewScheduler(0, 0, 0)
	assert.Equal(t, cap(s.workers), 40)
	assert.Equal(t, cap(s.inFlight), 40)
}

func TestSchedulerSentinel(t *testing.T) {
	assert.True(t, errors.Is(ErrMemoryBudget, ErrMemoryBudget))
}
