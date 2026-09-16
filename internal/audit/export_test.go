package audit

// Tamper edits a stored entry in place without repairing the chain, so the
// tests can show detection working. It lives in a test file because a method
// that rewrites history has no business on the production type.
func (l *Log) Tamper(seq uint64, mutate func(*Entry)) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for i := range l.entries {
		if l.entries[i].Seq == seq {
			mutate(&l.entries[i])
			return true
		}
	}
	return false
}

// Truncate drops the last n entries and touches nothing else, the way someone
// deleting the tail of a stored log would.
func (l *Log) Truncate(n int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = l.entries[:len(l.entries)-n]
}
