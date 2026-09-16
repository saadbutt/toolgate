package exec_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/saadbutt/toolgate/internal/exec"
	"github.com/saadbutt/toolgate/internal/tools"
)

func counterTool(hits *atomic.Int64, fail error) tools.Tool {
	return tools.Tool{
		Name: "count", Risk: tools.Write, Idempotent: true,
		Handler: func(context.Context, tools.Args) (tools.Result, error) {
			hits.Add(1)
			if fail != nil {
				return tools.Result{}, fail
			}
			return tools.Result{Text: "done"}, nil
		},
	}
}

func TestSameKeyRunsHandlerOnce(t *testing.T) {
	var hits atomic.Int64
	e := exec.New(nil)
	for i := 0; i < 5; i++ {
		if _, _, err := e.Do(context.Background(), "k", counterTool(&hits, nil), nil); err != nil {
			t.Fatal(err)
		}
	}
	if hits.Load() != 1 {
		t.Fatalf("handler ran %d times, want 1", hits.Load())
	}
}

func TestConcurrentSameKeyDoesNotDoubleExecute(t *testing.T) {
	var hits atomic.Int64
	e := exec.New(nil)
	tool := counterTool(&hits, nil)

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, _ = e.Do(context.Background(), "same", tool, nil)
		}()
	}
	wg.Wait()
	if hits.Load() != 1 {
		t.Fatalf("handler ran %d times under concurrency, want 1", hits.Load())
	}
}

// TestEffectSurvivesRecordingFailure is the partial-failure case: the refund
// happened, the write about it did not. The effect must not be forgotten.
func TestEffectSurvivesRecordingFailure(t *testing.T) {
	var hits atomic.Int64
	var recordOK atomic.Bool
	e := exec.New(func(exec.Record) error {
		if recordOK.Load() {
			return nil
		}
		return errors.New("database unavailable")
	})

	if _, _, err := e.Do(context.Background(), "k", counterTool(&hits, nil), nil); err != nil {
		t.Fatalf("Do returned an error even though the effect landed: %v", err)
	}
	st, _ := e.State("k")
	if st != exec.Applied {
		t.Fatalf("state is %v, want applied_unrecorded", st)
	}
	if len(e.Unrecorded()) != 1 {
		t.Fatal("unrecorded call not tracked")
	}

	recordOK.Store(true)
	fixed, err := e.Reconcile()
	if err != nil || fixed != 1 {
		t.Fatalf("reconcile fixed %d err %v", fixed, err)
	}
	if st, _ := e.State("k"); st != exec.Recorded {
		t.Fatalf("state after reconcile is %v", st)
	}
	if hits.Load() != 1 {
		t.Fatalf("reconcile re-ran the effect %d times", hits.Load())
	}
}

func TestFailedCallIsNotRetriedUnderSameKey(t *testing.T) {
	var hits atomic.Int64
	e := exec.New(nil)
	boom := errors.New("boom")
	tool := counterTool(&hits, boom)

	if _, _, err := e.Do(context.Background(), "k", tool, nil); err == nil {
		t.Fatal("expected failure")
	}
	_, replayed, err := e.Do(context.Background(), "k", tool, nil)
	if err == nil || !replayed {
		t.Fatalf("second attempt: replayed=%v err=%v", replayed, err)
	}
	if hits.Load() != 1 {
		t.Fatalf("handler ran %d times", hits.Load())
	}
}

// TestReconcileWritesEachRecordOnce covers overlapping reconcile passes, and a
// pass that starts while the first write is still in progress. Either would
// otherwise pick up the same applied call and record it twice.
func TestReconcileWritesEachRecordOnce(t *testing.T) {
	var hits atomic.Int64
	var writes atomic.Int64
	var recordOK atomic.Bool
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	var inFlight atomic.Int64
	e := exec.New(func(exec.Record) error {
		writes.Add(1)
		if !recordOK.Load() {
			return errors.New("database unavailable")
		}
		if inFlight.Add(1) > 1 {
			// A second write while the first is still going is the bug.
			// Return rather than block, so the test fails instead of hanging.
			inFlight.Add(-1)
			return nil
		}
		defer inFlight.Add(-1)
		once.Do(func() { close(started) })
		<-release
		return nil
	})

	// The first attempt fails, leaving one applied call.
	if _, _, err := e.Do(context.Background(), "k", counterTool(&hits, nil), nil); err != nil {
		t.Fatal(err)
	}
	recordOK.Store(true)

	var fixed atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			n, _ := e.Reconcile()
			fixed.Add(int64(n))
		}()
	}
	<-started
	// One write is in progress. Every other pass must see nothing to do.
	for i := 0; i < 8; i++ {
		if n, _ := e.Reconcile(); n != 0 {
			t.Errorf("a pass re-recorded a call whose write was in progress")
		}
	}
	close(release)
	wg.Wait()

	if got := writes.Load(); got != 2 {
		t.Fatalf("recorder called %d times, want 2: one failure and one reconcile", got)
	}
	if fixed.Load() != 1 {
		t.Fatalf("reconcile passes fixed %d in total, want 1", fixed.Load())
	}
	if st, _ := e.State("k"); st != exec.Recorded {
		t.Fatalf("state is %v, want recorded", st)
	}
}

// TestInFlightRecordIsNotReportedAsUnrecorded covers the window between the
// effect landing and its first write finishing. That call has not failed to
// record, so a reconcile pass must leave it alone.
func TestInFlightRecordIsNotReportedAsUnrecorded(t *testing.T) {
	var hits atomic.Int64
	started := make(chan struct{})
	release := make(chan struct{})
	e := exec.New(func(exec.Record) error {
		close(started)
		<-release
		return nil
	})

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _, _ = e.Do(context.Background(), "k", counterTool(&hits, nil), nil)
	}()
	<-started
	if un := e.Unrecorded(); len(un) != 0 {
		t.Errorf("a write still in progress was listed as unrecorded: %+v", un)
	}
	close(release)
	<-done
}
