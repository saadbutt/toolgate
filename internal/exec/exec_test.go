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

func panicTool(hits *atomic.Int64) tools.Tool {
	return tools.Tool{
		Name: "boom", Risk: tools.Write, Idempotent: true,
		Handler: func(context.Context, tools.Args) (tools.Result, error) {
			hits.Add(1)
			panic("nil map")
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

// TestFailedCallCanBeRetriedUnderSameKey covers a transient failure. A
// handler that returns an error is saying nothing happened, so the same key
// must be able to run again rather than replaying the error forever.
func TestFailedCallCanBeRetriedUnderSameKey(t *testing.T) {
	var hits atomic.Int64
	e := exec.New(nil)
	flaky := tools.Tool{
		Name: "flaky", Risk: tools.Write, Idempotent: true,
		Handler: func(context.Context, tools.Args) (tools.Result, error) {
			if hits.Add(1) == 1 {
				return tools.Result{}, errors.New("connection reset")
			}
			return tools.Result{Text: "done"}, nil
		},
	}

	if _, _, err := e.Do(context.Background(), "k", flaky, nil); err == nil {
		t.Fatal("expected the first attempt to fail")
	}
	res, replayed, err := e.Do(context.Background(), "k", flaky, nil)
	if err != nil || replayed || res.Text != "done" {
		t.Fatalf("retry: result=%q replayed=%v err=%v", res.Text, replayed, err)
	}
	if hits.Load() != 2 {
		t.Fatalf("handler ran %d times, want 2", hits.Load())
	}
}

// TestPanickingHandlerDoesNotWedgeItsKey covers a handler that panics. The
// panic must not escape into the caller, and the key must not be left at
// Started, where nothing lists it and nothing can clear it. Nobody knows
// whether the effect happened, so the key is held and listed, not retried.
func TestPanickingHandlerDoesNotWedgeItsKey(t *testing.T) {
	var hits atomic.Int64
	e := exec.New(nil)

	var err error
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("handler panic escaped Do: %v", r)
			}
		}()
		_, _, err = e.Do(context.Background(), "k", panicTool(&hits), nil)
	}()
	if !errors.Is(err, exec.ErrOutcomeUnknown) {
		t.Fatalf("panic reported as %v", err)
	}
	if st, _ := e.State("k"); st != exec.Unknown {
		t.Fatalf("state is %v, want outcome_unknown", st)
	}
	if un := e.Unresolved(); len(un) != 1 || un[0].Key != "k" {
		t.Fatalf("unresolved: %+v", un)
	}

	// Running it again could repeat an effect that already happened.
	if _, _, err := e.Do(context.Background(), "k", counterTool(&hits, nil), nil); !errors.Is(err, exec.ErrOutcomeUnknown) {
		t.Fatalf("retry of an unknown outcome: %v", err)
	}
	if hits.Load() != 1 {
		t.Fatalf("handler ran %d times, want 1", hits.Load())
	}
}

func TestResolvingAsNotAppliedLetsTheKeyRunAgain(t *testing.T) {
	var hits atomic.Int64
	e := exec.New(nil)
	_, _, _ = e.Do(context.Background(), "k", panicTool(&hits), nil)

	if err := e.Resolve("k", false); err != nil {
		t.Fatal(err)
	}
	res, replayed, err := e.Do(context.Background(), "k", counterTool(&hits, nil), nil)
	if err != nil || replayed || res.Text != "done" {
		t.Fatalf("after resolving as not applied: result=%q replayed=%v err=%v", res.Text, replayed, err)
	}
	if len(e.Unresolved()) != 0 {
		t.Fatal("resolved key still listed as unresolved")
	}
}

// TestResolvingAsAppliedReplaysAndReconciles covers the other answer. The
// effect happened, so a repeat must not run it again, and the record that was
// never written is written by Reconcile.
func TestResolvingAsAppliedReplaysAndReconciles(t *testing.T) {
	var hits, writes atomic.Int64
	e := exec.New(func(exec.Record) error { writes.Add(1); return nil })
	_, _, _ = e.Do(context.Background(), "k", panicTool(&hits), nil)

	if err := e.Resolve("k", true); err != nil {
		t.Fatal(err)
	}
	if un := e.Unrecorded(); len(un) != 1 {
		t.Fatalf("applied call not listed as unrecorded: %+v", un)
	}
	if fixed, err := e.Reconcile(); err != nil || fixed != 1 || writes.Load() != 1 {
		t.Fatalf("reconcile fixed %d, wrote %d, err %v", fixed, writes.Load(), err)
	}
	if _, replayed, err := e.Do(context.Background(), "k", counterTool(&hits, nil), nil); err != nil || !replayed {
		t.Fatalf("repeat after resolving as applied: replayed=%v err=%v", replayed, err)
	}
	if hits.Load() != 1 {
		t.Fatalf("handler ran %d times, want 1", hits.Load())
	}
}

func TestResolveRefusesAKeyWithNoUnknownOutcome(t *testing.T) {
	var hits atomic.Int64
	e := exec.New(nil)
	if err := e.Resolve("missing", true); !errors.Is(err, exec.ErrNothingToResolve) {
		t.Fatalf("missing key: %v", err)
	}
	_, _, _ = e.Do(context.Background(), "done", counterTool(&hits, nil), nil)
	if err := e.Resolve("done", false); !errors.Is(err, exec.ErrNothingToResolve) {
		t.Fatalf("recorded key: %v", err)
	}
	if st, _ := e.State("done"); st != exec.Recorded {
		t.Fatalf("resolve changed a recorded call to %v", st)
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
