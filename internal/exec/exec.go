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
	// Failed means the handler returned an error and nothing happened.
	Failed
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

// ErrInFlight means the same key is currently executing elsewhere.
var ErrInFlight = errors.New("exec: a call with this idempotency key is in flight")

// Recorder persists the fact that a call happened. In this reference
// implementation it is the audit log; in a deployment it would be a row in
// the same database the effect was written to.
type Recorder func(rec Record) error

// Executor runs handlers with at-most-once semantics per key.
type Executor struct {
	mu      sync.Mutex
	records map[string]*Record
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
func (e *Executor) Do(ctx context.Context, key string, t tools.Tool, args tools.Args) (tools.Result, bool, error) {
	e.mu.Lock()
	if prev, ok := e.records[key]; ok {
		switch prev.State {
		case Recorded, Applied:
			res := prev.Result
			e.mu.Unlock()
			return res, true, nil
		case Failed:
			errStr := prev.Err
			e.mu.Unlock()
			return tools.Result{}, true, errors.New(errStr)
		default:
			e.mu.Unlock()
			return tools.Result{}, false, ErrInFlight
		}
	}
	rec := &Record{Key: key, Tool: t.Name, State: Started, Started: e.now()}
	e.records[key] = rec
	e.mu.Unlock()

	res, err := t.Handler(ctx, args)

	e.mu.Lock()
	rec.Ended = e.now()
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
	snapshot := *rec
	e.mu.Unlock()

	if rerr := e.record(snapshot); rerr != nil {
		// Deliberately not rolled back. The effect is real and pretending
		// otherwise would be a lie with financial consequences. It stays
		// Applied for Reconcile to finish.
		return res, false, nil
	}

	e.mu.Lock()
	rec.State = Recorded
	e.mu.Unlock()
	return res, false, nil
}

// Unrecorded lists calls whose effect happened but whose record did not.
func (e *Executor) Unrecorded() []Record {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []Record
	for _, r := range e.records {
		if r.State == Applied {
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
func (e *Executor) Reconcile() (fixed int, err error) {
	for _, r := range e.Unrecorded() {
		if rerr := e.record(r); rerr != nil {
			err = fmt.Errorf("exec: reconciling %s: %w", r.Key, rerr)
			continue
		}
		e.mu.Lock()
		if live, ok := e.records[r.Key]; ok {
			live.State = Recorded
		}
		e.mu.Unlock()
		fixed++
	}
	return fixed, err
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
