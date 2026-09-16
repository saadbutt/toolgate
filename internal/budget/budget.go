// Package budget stops an agent that is wrong in a loop.
//
// Three separate ceilings, because they fail differently. Money is the one
// that shows up on a statement. Tokens are the one that shows up on an
// invoice. Steps are the one that catches a model retrying the same broken
// call four hundred times, which is the failure that actually happens.
package budget

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// Limits is a ceiling set. Zero in any field means that dimension is
// unlimited, which should be rare and deliberate.
type Limits struct {
	MaxSteps  int
	MaxTokens int64
	// MaxMoney is in minor units, over the whole window.
	MaxMoney int64
	// Window is how long a ledger accumulates before resetting.
	Window time.Duration
}

// ErrExceeded is returned when a ceiling is hit.
type ErrExceeded struct {
	Dimension string
	Used      int64
	Limit     int64
}

func (e *ErrExceeded) Error() string {
	return fmt.Sprintf("budget: %s ceiling reached (%d of %d)", e.Dimension, e.Used, e.Limit)
}

// Is lets callers match with errors.Is(err, budget.Exceeded).
func (e *ErrExceeded) Is(target error) bool { return target == Exceeded }

// Exceeded is the sentinel for any ceiling breach.
var Exceeded = errors.New("budget exceeded")

type ledger struct {
	steps  int
	tokens int64
	money  int64
	opened time.Time
}

// Ledger tracks consumption per principal. Safe for concurrent use.
type Ledger struct {
	mu     sync.Mutex
	limits Limits
	per    map[string]*ledger
	now    func() time.Time
}

// New returns a Ledger enforcing limits.
func New(limits Limits) *Ledger {
	if limits.Window <= 0 {
		limits.Window = time.Hour
	}
	return &Ledger{
		limits: limits,
		per:    make(map[string]*ledger),
		now:    time.Now,
	}
}

// SetClock replaces the time source for tests.
func (l *Ledger) SetClock(f func() time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.now = f
}

// Charge records consumption for a principal, or refuses it.
//
// The check and the increment happen under one lock. Splitting them into
// "may I" and "I did" is how concurrent agents both pass a check that only
// one of them should have.
func (l *Ledger) Charge(principal string, tokens, money int64) error {
	return l.charge(principal, 1, tokens, money)
}

// ChargeMoney records money against a principal without counting a step.
//
// A gate charges the step the moment a call arrives, before anything about it
// is known to be valid, and only learns the amount once the arguments have
// been validated. Counting a second step for the same call would quietly halve
// the ceiling.
func (l *Ledger) ChargeMoney(principal string, money int64) error {
	return l.charge(principal, 0, 0, money)
}

func (l *Ledger) charge(principal string, steps int, tokens, money int64) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	led, ok := l.per[principal]
	if !ok || now.Sub(led.opened) >= l.limits.Window {
		led = &ledger{opened: now}
		l.per[principal] = led
	}

	if l.limits.MaxSteps > 0 && led.steps+steps > l.limits.MaxSteps {
		return &ErrExceeded{Dimension: "steps", Used: int64(led.steps), Limit: int64(l.limits.MaxSteps)}
	}
	if l.limits.MaxTokens > 0 && led.tokens+tokens > l.limits.MaxTokens {
		return &ErrExceeded{Dimension: "tokens", Used: led.tokens, Limit: l.limits.MaxTokens}
	}
	if l.limits.MaxMoney > 0 && led.money+money > l.limits.MaxMoney {
		return &ErrExceeded{Dimension: "money", Used: led.money, Limit: l.limits.MaxMoney}
	}

	led.steps += steps
	led.tokens += tokens
	led.money += money
	return nil
}

// Usage reports current consumption for a principal.
func (l *Ledger) Usage(principal string) (steps int, tokens, money int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	led, ok := l.per[principal]
	if !ok {
		return 0, 0, 0
	}
	if l.now().Sub(led.opened) >= l.limits.Window {
		return 0, 0, 0
	}
	return led.steps, led.tokens, led.money
}

// Limits returns the configured ceilings.
func (l *Ledger) Limits() Limits { return l.limits }
