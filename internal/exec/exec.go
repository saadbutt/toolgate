// Package exec runs tool handlers exactly once per idempotency key, and knows
// what to do when the action succeeded but recording it did not.
//
// The second half is the part that gets skipped. An agent issues a refund, the
// money moves, the audit write fails, the process restarts. Without explicit
// state the system either believes the refund never happened, and repeats it,
// or forgets it entirely. Neither is acceptable when the effect was real.
package exec

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/saadbutt/toolgate/internal/tools"
)

// State is where a call got to.
type State int

const (
	// Started means the handler is running and the outcome is unknown.
	Started State = iota
	// Applied means the effect happened but the record has not been
	// confirmed. This is the state that exists to be reconciled.
	Applied
	// Recorded means effect and record are both durable.
	Recorded
	// Failed means the handler returned an error and nothing happened. The
	// same key may run again.
	Failed
	// Unknown means the handler panicked, so nobody knows whether the effect
	// happened. The key is held until someone checks and calls Resolve.
	Unknown
)

func (s State) String() string {
	switch s {
	case Started:
		return "started"
	case Applied:
		return "applied_unrecorded"
	case Recorded:
		return "recorded"
	case Failed:
		return "failed"
	case Unknown:
		return "outcome_unknown"
	default:
		return "unknown"
	}
}

// Record is the durable trace of one execution attempt.
type Record struct {
	Key     string
	Tool    string
	State   State
	Result  tools.Result
	Err     string
	Started time.Time
	Ended   time.Time
}

var (
	// ErrInFlight means the same key is currently executing elsewhere.
	ErrInFlight = errors.New("exec: a call with this idempotency key is in flight")
	// ErrOutcomeUnknown means a handler panicked under this key. Running it
	// again could repeat an effect that already happened, so it does not run
	// until Resolve settles what happened.
	ErrOutcomeUnknown = errors.New("exec: handler panicked, outcome unknown")
	// ErrNothingToResolve means Resolve was called on a key whose outcome is
	// not unknown.
	ErrNothingToResolve = errors.New("exec: no unknown outcome under this key")
)

// Recorder persists the fact that a call happened. In this reference
// implementation it is the audit log; in a deployment it would be a row in
// the same database the effect was written to.
type Recorder func(rec Record) error

// Executor runs handlers with at-most-once semantics per key.
type Executor struct {
	mu      sync.Mutex
	records map[string]*Record
	// writing holds keys whose record is being written right now. Nothing
	// else may start writing them, or the same effect is recorded twice.
	writing map[string]bool
	record  Recorder
	now     func() time.Time
}

// New returns an Executor that calls record after each successful handler.
func New(record Recorder) *Executor {
	if record == nil {
		record = func(Record) error { return nil }
	}
	return &Executor{
		records: make(map[string]*Record),
		writing: make(map[string]bool),
		record:  record,
		now:     time.Now,
	}
}

// SetClock replaces the time source for tests.
func (e *Executor) SetClock(f func() time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.now = f
}

// Do runs the tool once for the given key.
//
// A repeat with the same key returns the first result without running the
// handler again. That is the entire point: retries are normal, and the
// caller cannot always tell whether the first attempt landed.
//
// A key whose handler returned an error runs again, because an error means
// nothing happened. A key whose handler panicked does not, because nobody
// knows whether anything happened.
func (e *Executor) Do(ctx context.Context, key string, t tools.Tool, args tools.Args) (tools.Result, bool, error) {
	e.mu.Lock()
	if prev, ok := e.records[key]; ok {
		switch prev.State {
		case Recorded, Applied:
			res := prev.Result
			e.mu.Unlock()
			return res, true, nil
		case Failed:
			// Nothing happened last time. This attempt replaces that record.
		case Unknown:
			e.mu.Unlock()
			return tools.Result{}, false, fmt.Errorf("%w: resolve %q before retrying", ErrOutcomeUnknown, key)
		default:
			e.mu.Unlock()
			return tools.Result{}, false, ErrInFlight
		}
	}
	rec := &Record{Key: key, Tool: t.Name, State: Started, Started: e.now()}
	e.records[key] = rec
	e.mu.Unlock()

	res, panicked, err := run(ctx, t, args)

	e.mu.Lock()
	rec.Ended = e.now()
	if panicked {
		rec.State = Unknown
		rec.Err = err.Error()
		e.mu.Unlock()
		return tools.Result{}, false, err
	}
	if err != nil {
		rec.State = Failed
		rec.Err = err.Error()
		e.mu.Unlock()
		return tools.Result{}, false, err
	}
	// The effect has happened. From here the only correct behaviour is to
	// remember it, so the state moves to Applied before recording is tried.
	rec.State = Applied
	rec.Result = res
	e.writing[key] = true
	snapshot := *rec
	e.mu.Unlock()

	rerr := e.record(snapshot)

	e.mu.Lock()
	delete(e.writing, key)
	// A failed write is deliberately not rolled back. The effect is real and
	// pretending otherwise would be a lie with financial consequences. It
	// stays Applied for Reconcile to finish.
	if rerr == nil {
		rec.State = Recorded
	}
	e.mu.Unlock()
	return res, false, nil
}

// run calls the handler and turns a panic into an error, so that one broken
// handler neither takes the process down nor leaves its key at Started, where
// nothing lists it and nothing can clear it.
func run(ctx context.Context, t tools.Tool, args tools.Args) (res tools.Result, panicked bool, err error) {
	defer func() {
		if r := recover(); r != nil {
			res, panicked, err = tools.Result{}, true, fmt.Errorf("%w: %v", ErrOutcomeUnknown, r)
		}
	}()
	res, err = t.Handler(ctx, args)
	return res, false, err
}

// Unresolved lists calls whose handler panicked. Each may or may not have had
// its effect, and each key stays blocked until Resolve says which.
func (e *Executor) Unresolved() []Record {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []Record
	for _, r := range e.records {
		if r.State == Unknown {
			out = append(out, *r)
		}
	}
	return out
}

// Resolve settles a call whose outcome is unknown, once someone has checked
// the system its handler talks to.
//
// applied=true means the effect happened: the call becomes Applied, so a
// repeat replays instead of running again, and Reconcile records it.
// applied=false means it did not: the call becomes Failed and the key can run
// again. Nothing here guesses, because either guess is wrong half the time
// and one of the wrong halves moves money twice.
func (e *Executor) Resolve(key string, applied bool) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	r, ok := e.records[key]
	if !ok || r.State != Unknown {
		return fmt.Errorf("%w: %q", ErrNothingToResolve, key)
	}
	if applied {
		r.State = Applied
	} else {
		r.State = Failed
	}
	return nil
}

// Unrecorded lists calls whose effect happened but whose record did not. A
// call whose write is still in progress has not failed yet and is not listed.
func (e *Executor) Unrecorded() []Record {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []Record
	for key, r := range e.records {
		if r.State == Applied && !e.writing[key] {
			out = append(out, *r)
		}
	}
	return out
}

// Reconcile retries recording for every Applied call.
//
// This is the pass that a real deployment runs on a timer and after every
// restart. It is not a nicety; without it the Applied state accumulates
// silently and the audit log is quietly incomplete.
//
// Each call is claimed before it is written, so passes that overlap, or that
// start while Do is still writing, never record the same effect twice.
func (e *Executor) Reconcile() (fixed int, err error) {
	e.mu.Lock()
	var claimed []Record
	for key, r := range e.records {
		if r.State == Applied && !e.writing[key] {
			e.writing[key] = true
			claimed = append(claimed, *r)
		}
	}
	e.mu.Unlock()

	var errs []error
	for _, r := range claimed {
		rerr := e.record(r)
		e.mu.Lock()
		delete(e.writing, r.Key)
		if rerr == nil {
			e.records[r.Key].State = Recorded
		}
		e.mu.Unlock()
		if rerr != nil {
			errs = append(errs, fmt.Errorf("exec: reconciling %s: %w", r.Key, rerr))
			continue
		}
		fixed++
	}
	return fixed, errors.Join(errs...)
}

// State reports where a key got to.
func (e *Executor) State(key string) (State, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	r, ok := e.records[key]
	if !ok {
		return Failed, false
	}
	return r.State, true
}
