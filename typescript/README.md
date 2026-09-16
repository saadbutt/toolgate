# toolgate, confirmation core (TypeScript)

The one piece of [toolgate](../) most worth having in your own stack, ported to TypeScript.

```
node --experimental-strip-types --test test/*.test.ts   # 28 tests
node --experimental-strip-types src/demo.ts             # the demo
```

Node 22.6 or newer. No build step, no install, **zero runtime dependencies**.

## What this is

A human approves an action. Some time passes. The action executes.

If the arguments are supplied again at execution time, the approval covered a description and the effect was something else. That is the bug this prevents, and it is easy to write by accident:

```ts
// The shape that looks fine and is not
const plan = await model.plan(request);
await showToHuman(plan.summary);
if (await human.approves()) {
  const args = await model.finalArgs();   // asked again, after approval
  await issueRefund(args);                // approved $42, refunding $4,200
}
```

Here the arguments are frozen when the intent is created, and `confirm` hands back the frozen copy. `confirmAndRun` takes no arguments at all, so a caller cannot supply different ones.

## The demo

```
The agent asks to refund $42.00
  nothing executed. intent 24a6c7c1 awaits saad
  args hash:  a8c23bbb2d44e375

The amount is swapped to $4,200.00 after approval
  tampered hash: 6b463c3b380d3781
  rejected: arguments do not match what was approved

Saad approves
  refunded $42.00 against INV-1002
  executed the approved amount, not the swapped one

The same token is presented again
  rejected: intent already used
```

## Cross-language parity

`hashArgs` here and `confirm.HashArgs` in the Go implementation produce identical hashes for identical arguments. Both test suites pin the same seven fixtures, covering HTML-sensitive characters, line and paragraph separators, non-ASCII text and control characters, so a change to either encoder that affects one of those cases fails a test.

That matters in practice: an agent runtime in TypeScript and an approval service in Go have to agree on what was approved, byte for byte.

Getting it to match took two non-obvious things, both places where Go's `encoding/json` escapes and `JSON.stringify` does not:

- `<`, `>` and `&` become `\u003c`, `\u003e` and `\u0026`. Everything agrees until an argument contains an ampersand.
- U+2028 and U+2029, the line and paragraph separators, become `\u2028` and `\u2029`. These arrive in ordinary text pasted from PDFs and web pages. The first version of this port missed them, and the fixtures at the time did not notice, which is why they are pinned now.

See `src/canonical.ts`.

Two other decisions, both to keep the implementations honest with each other:

- **Fractional numbers throw** rather than round. `10.7` cents is refused.
- **Integers past `Number.MAX_SAFE_INTEGER` throw.** Beyond 2^53 a JavaScript number cannot represent every `int64`, so the two sides would stop agreeing. Failing at the boundary beats diverging quietly.

## API

```ts
const store = new IntentStore({ ttlMs: 60_000 });

// Freeze the request. Nothing executes.
const { intent, token } = store.create(
  "issue_refund",
  { invoice_id: "INV-1002", amount_cents: 4200, reason: "duplicate charge" },
  "Issue a refund | INV-1002 | $42.00",   // what the human reads
  "agent-1",                              // who asked
  "saad",                                 // who may approve
);

// Execution takes a token, never arguments.
const result = await confirmAndRun(store, intent.id, token, "saad", {
  issue_refund: (args) => billing.refund(args),
});
```

`store.verifyArgs(id, args)` exists for callers that carry arguments alongside a token and want to prove they were not swapped in transit. The gate itself does not need it, because it executes the frozen copy.

## Properties the tests assert

- Confirm returns the frozen arguments, not anything supplied later
- Mutating the caller's object after `create` does not change the intent
- Mutating the object returned by `pending` does not change the intent
- Tokens are single use, including under concurrent confirmation
- Only the named approver can confirm
- Expired intents are refused
- A one-cent change fails verification
- Reading an intent never reveals the token
- Wrong and short tokens both fail as `bad_token`, without `timingSafeEqual` throwing

## Limits

**In memory.** Intents live in a `Map`. A real deployment puts them in the same database as the effect, so an approval and a refund commit together.

**Single process.** Confirmation is safe here because Node runs one event-loop turn at a time and `confirm` contains no `await`. Across processes you need the store's uniqueness guarantee to come from the database, typically a conditional update on a `used` column.

**Constant-time comparison is not constant-time lookup.** Token comparison uses `timingSafeEqual`, but the `Map` lookup by id is not hardened. Intent ids are random and not secret, so this is the right trade here, and it is worth knowing rather than assuming.

**This is one component, not the system.** Policy, budgets, the audit chain, idempotent execution and untrusted-content handling are in the Go implementation in the parent directory.

## Typechecking

The runtime has no dependencies. Typechecking is optional and needs dev tooling:

```
npm install
npm run typecheck
```

Tests run without it, because `--experimental-strip-types` removes types rather than checking them.
