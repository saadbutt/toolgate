package budget_test

import (
	"errors"
	"math"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/saadbutt/toolgate/internal/budget"
)

func TestStepCeilingStops(t *testing.T) {
	l := budget.New(budget.Limits{MaxSteps: 3, Window: time.Hour})
	for i := 0; i < 3; i++ {
		if err := l.Charge("a", 0, 0); err != nil {
			t.Fatalf("step %d refused early: %v", i, err)
		}
	}
	if err := l.Charge("a", 0, 0); !errors.Is(err, budget.Exceeded) {
		t.Fatalf("fourth step allowed: %v", err)
	}
}

func TestMoneyCeilingStops(t *testing.T) {
	l := budget.New(budget.Limits{MaxMoney: 10_000, Window: time.Hour})
	if err := l.Charge("a", 0, 9_000); err != nil {
		t.Fatal(err)
	}
	if err := l.Charge("a", 0, 2_000); !errors.Is(err, budget.Exceeded) {
		t.Fatalf("overspend allowed: %v", err)
	}
}

func TestRefusedChargeDoesNotConsume(t *testing.T) {
	l := budget.New(budget.Limits{MaxMoney: 10_000, Window: time.Hour})
	_ = l.Charge("a", 0, 9_000)
	_ = l.Charge("a", 0, 5_000) // refused
	if _, _, money := l.Usage("a"); money != 9_000 {
		t.Fatalf("refused charge moved the ledger to %d", money)
	}
}

func TestPrincipalsAreIndependent(t *testing.T) {
	l := budget.New(budget.Limits{MaxSteps: 1, Window: time.Hour})
	if err := l.Charge("a", 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := l.Charge("b", 0, 0); err != nil {
		t.Fatalf("principal b blocked by principal a: %v", err)
	}
}

func TestWindowResets(t *testing.T) {
	l := budget.New(budget.Limits{MaxSteps: 1, Window: time.Minute})
	now := time.Now()
	l.SetClock(func() time.Time { return now })

	_ = l.Charge("a", 0, 0)
	if err := l.Charge("a", 0, 0); err == nil {
		t.Fatal("second step in window allowed")
	}
	now = now.Add(2 * time.Minute)
	if err := l.Charge("a", 0, 0); err != nil {
		t.Fatalf("new window still blocked: %v", err)
	}
}

// TestConcurrentChargesRespectTheCeiling covers the check-then-increment race.
func TestConcurrentChargesRespectTheCeiling(t *testing.T) {
	const ceiling = 20
	l := budget.New(budget.Limits{MaxSteps: ceiling, Window: time.Hour})

	var ok atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := l.Charge("a", 0, 0); err == nil {
				ok.Add(1)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != ceiling {
		t.Fatalf("%d charges passed a ceiling of %d", ok.Load(), ceiling)
	}
}

// TestChargeMoneyDoesNotCountAStep guards the split the gate relies on: one
// step when a call arrives, its money once the amount is known.
func TestChargeMoneyDoesNotCountAStep(t *testing.T) {
	l := budget.New(budget.Limits{MaxSteps: 1, MaxMoney: 10_000, Window: time.Hour})
	if err := l.Charge("a", 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := l.ChargeMoney("a", 9_000); err != nil {
		t.Fatalf("money refused by the step ceiling: %v", err)
	}
	if steps, _, money := l.Usage("a"); steps != 1 || money != 9_000 {
		t.Fatalf("usage is %d steps, %d money", steps, money)
	}
	if err := l.ChargeMoney("a", 2_000); !errors.Is(err, budget.Exceeded) {
		t.Fatalf("overspend allowed: %v", err)
	}
}

// TestChargeCannotWrapTheLedger covers int64 overflow. A charge near the top
// of the range used to wrap the running total negative, passing the check and
// leaving room for everything after it.
func TestChargeCannotWrapTheLedger(t *testing.T) {
	l := budget.New(budget.Limits{MaxMoney: 10_000, MaxTokens: 10_000, Window: time.Hour})
	if err := l.Charge("a", 100, 100); err != nil {
		t.Fatal(err)
	}
	if err := l.ChargeMoney("a", math.MaxInt64); !errors.Is(err, budget.Exceeded) {
		t.Fatalf("money charge near MaxInt64 allowed: %v", err)
	}
	if err := l.Charge("a", math.MaxInt64, 0); !errors.Is(err, budget.Exceeded) {
		t.Fatalf("token charge near MaxInt64 allowed: %v", err)
	}
	if _, tokens, money := l.Usage("a"); tokens != 100 || money != 100 {
		t.Fatalf("ledger moved to tokens=%d money=%d", tokens, money)
	}
}

// TestUnlimitedDimensionCannotWrap covers a dimension with no ceiling. It
// still cannot pass the end of the int64 range.
func TestUnlimitedDimensionCannotWrap(t *testing.T) {
	l := budget.New(budget.Limits{Window: time.Hour})
	if err := l.ChargeMoney("a", math.MaxInt64); err != nil {
		t.Fatal(err)
	}
	if err := l.ChargeMoney("a", 1); err == nil {
		t.Fatal("unlimited money total wrapped past MaxInt64")
	}
	if _, _, money := l.Usage("a"); money != math.MaxInt64 {
		t.Fatalf("ledger moved to %d", money)
	}
}

// TestNegativeChargesAreRefused covers a caller paying the ledger back.
func TestNegativeChargesAreRefused(t *testing.T) {
	l := budget.New(budget.Limits{MaxTokens: 1_000, MaxMoney: 1_000, Window: time.Hour})
	_ = l.Charge("a", 900, 900)
	if err := l.Charge("a", -900, 0); !errors.Is(err, budget.ErrNegativeCharge) {
		t.Fatalf("negative tokens accepted: %v", err)
	}
	if err := l.ChargeMoney("a", -900); !errors.Is(err, budget.ErrNegativeCharge) {
		t.Fatalf("negative money accepted: %v", err)
	}
	if steps, tokens, money := l.Usage("a"); steps != 1 || tokens != 900 || money != 900 {
		t.Fatalf("ledger moved to steps=%d tokens=%d money=%d", steps, tokens, money)
	}
}
