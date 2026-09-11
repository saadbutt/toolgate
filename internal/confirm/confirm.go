// Package confirm implements the gap between a human approving an action and
// that action happening.
//
// The bug this package exists to prevent: approving a description and then
// executing something else. If the arguments are re-supplied by the agent
// after approval, the approval covered nothing. Here the arguments are frozen
// at the moment the intent is created, and execution uses the frozen copy.
package confirm

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/saadbutt/toolgate/internal/tools"
)

var (
	// ErrNotFound means no pending intent has that id.
	ErrNotFound = errors.New("confirm: no such intent")
	// ErrExpired means the approval window closed.
	ErrExpired = errors.New("confirm: intent expired")
	// ErrAlreadyUsed means the token was presented twice.
	ErrAlreadyUsed = errors.New("confirm: intent already used")
	// ErrBadToken means the token did not match.
	ErrBadToken = errors.New("confirm: token mismatch")
	// ErrWrongApprover means someone other than the intended approver tried
	// to confirm.
	ErrWrongApprover = errors.New("confirm: principal may not approve this intent")
	// ErrArgsMismatch means the arguments presented at execution differ from
	// the ones that were approved.
	ErrArgsMismatch = errors.New("confirm: arguments do not match what was approved")
)

// Intent is a consequential action waiting for a human.
type Intent struct {
	ID string
	// Tool and Args are the frozen request. Args is the copy that executes.
	Tool string
	Args tools.Args
	// ArgsHash is over the canonical encoding of Args, and is what makes
	// tampering detectable rather than merely unlikely.
	ArgsHash string
	// Summary is the sentence a human actually reads before approving.
	Summary string
	// RequestedBy is the agent that asked. Approver is who may say yes.
	RequestedBy string
	Approver    string
	CreatedAt   time.Time
	ExpiresAt   time.Time

	token []byte
	used  bool
}

// Store holds pending intents. Safe for concurrent use.
type Store struct {
	mu      sync.Mutex
	intents map[string]*Intent
	ttl     time.Duration
	now     func() time.Time
}

// NewStore returns a Store whose intents expire after ttl.
//
// A short ttl is part of the security model, not an ergonomic detail. An
// approval that stays valid for a day is an approval for a situation that no
// longer exists.
func NewStore(ttl time.Duration) *Store {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &Store{
		intents: make(map[string]*Intent),
		ttl:     ttl,
		now:     time.Now,
	}
}

// SetClock replaces the time source. Tests use it; production does not.
func (s *Store) SetClock(f func() time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.now = f
}

// Create freezes a request and returns the intent plus its one-time token.
//
// The token is returned once and never stored in recoverable form. Reading
// the store does not let you approve anything.
func (s *Store) Create(toolName string, args tools.Args, summary, requestedBy, approver string) (*Intent, string, error) {
	hash, err := HashArgs(args)
	if err != nil {
		return nil, "", err
	}

	idRaw := make([]byte, 12)
	if _, err := rand.Read(idRaw); err != nil {
		return nil, "", fmt.Errorf("confirm: generating id: %w", err)
	}
	tokRaw := make([]byte, 32)
	if _, err := rand.Read(tokRaw); err != nil {
		return nil, "", fmt.Errorf("confirm: generating token: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()

	in := &Intent{
		ID:          hex.EncodeToString(idRaw),
		Tool:        toolName,
		Args:        cloneArgs(args),
		ArgsHash:    hash,
		Summary:     summary,
		RequestedBy: requestedBy,
		Approver:    approver,
		CreatedAt:   now,
		ExpiresAt:   now.Add(s.ttl),
		token:       tokRaw,
	}
	s.intents[in.ID] = in
	return in, hex.EncodeToString(tokRaw), nil
}

// Pending returns an intent for display without consuming it.
func (s *Store) Pending(id string) (*Intent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	in, ok := s.intents[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *in
	cp.Args = cloneArgs(in.Args)
	cp.token = nil
	return &cp, nil
}

// Confirm consumes the intent and returns the frozen arguments.
//
// Everything that could go wrong is checked before the intent is marked used,
// and the intent is marked used before the arguments are returned, so a
// concurrent second attempt loses.
func (s *Store) Confirm(id, token, approver string) (string, tools.Args, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	in, ok := s.intents[id]
	if !ok {
		return "", nil, ErrNotFound
	}
	if in.used {
		return "", nil, ErrAlreadyUsed
	}
	if s.now().After(in.ExpiresAt) {
		return "", nil, ErrExpired
	}
	if approver != in.Approver {
		return "", nil, ErrWrongApprover
	}
	raw, err := hex.DecodeString(token)
	if err != nil || subtle.ConstantTimeCompare(raw, in.token) != 1 {
		return "", nil, ErrBadToken
	}

	in.used = true
	return in.Tool, cloneArgs(in.Args), nil
}

// VerifyArgs reports whether args are byte-identical to what was approved.
//
// The gate does not need this, because it executes the frozen copy. It exists
// so a caller that carries arguments alongside a token can prove they were not
// swapped in transit, and so the demo can show the tampering case failing.
func (s *Store) VerifyArgs(id string, args tools.Args) error {
	s.mu.Lock()
	in, ok := s.intents[id]
	s.mu.Unlock()
	if !ok {
		return ErrNotFound
	}
	h, err := HashArgs(args)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(h), []byte(in.ArgsHash)) != 1 {
		return ErrArgsMismatch
	}
	return nil
}

// Reap deletes expired intents and reports how many went.
func (s *Store) Reap() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	n := 0
	for id, in := range s.intents {
		if now.After(in.ExpiresAt) {
			delete(s.intents, id)
			n++
		}
	}
	return n
}

// HashArgs returns a stable hash over the canonical encoding of args.
//
// encoding/json sorts map keys, so the encoding is deterministic for the
// value types the tools package permits. That determinism is load-bearing:
// if two encodings of the same arguments could differ, a legitimate
// confirmation would sometimes fail and the check would get disabled.
func HashArgs(args tools.Args) (string, error) {
	b, err := json.Marshal(map[string]any(args))
	if err != nil {
		return "", fmt.Errorf("confirm: encoding args: %w", err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func cloneArgs(in tools.Args) tools.Args {
	out := make(tools.Args, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
