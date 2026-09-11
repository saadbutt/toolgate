# toolgate

A gate between an AI agent and the systems it can actually change.

The model decides what it wants to do. The gate decides what is allowed to happen.

Go, standard library only. No dependencies.

```
go run ./cmd/demo
```

No API key needed. Seven scenarios, each one an attack and the guardrail that stops it.

## What this is not

Not a framework for building agents. Not an orchestrator, a prompt library, or a vector store. Those are solved elsewhere.

This is the layer you put underneath an agent so that a bad model output cannot become a bad outcome.

## The problem

There are thousands of repositories showing an agent calling a tool. There are very few showing what happens when the agent is wrong, manipulated, or stuck in a loop.

Once an agent can move money, send messages, or change records, "it usually gets it right" stops being good enough. The interesting engineering is entirely in the failure cases.

## What the demo shows

| # | Scenario | What stops it |
|---|---|---|
| 1 | Agent tries to issue a refund directly | Consequential actions become a pending intent, never an execution |
| 2 | Refund above the agent's cap | Cap lives on the capability grant, checked before a human is ever asked |
| 3 | Retrieved document instructs the agent to escalate | Authority is computed from the principal. Reading cannot widen it |
| 4 | Approval token replayed | Single use, enforced under lock |
| 5 | Arguments swapped between approval and execution | Execution uses the frozen copy. It does not accept arguments |
| 6 | Agent loops on a failing call | Step ceiling, charged before the policy decision |
| 7 | Audit entry edited by hand | Hash chain breaks and names the entry |

Scenario 5 is the one worth reading the code for. "Confirm before executing" is easy to implement wrongly: if you re-ask the model for arguments after approval, you approved a description and executed something else.

## Design

Every call takes one path, in this order:

```
validate -> charge budget -> decide -> execute -> record
```

Nothing lets a caller skip a step or reorder them. Every interesting failure in agent systems comes from a step that was skipped once, for a good reason, in a hurry.

### Arguments are validated before anything sees them

Model output is a request, not a fact. It is checked against a declared schema and refused if it does not match, rather than coerced into something plausible.

Unknown fields are rejected, not ignored. `10.7` cents is refused, not truncated. Errors name the field and the bound, so an agent can correct itself.

### Authority comes from the principal and nothing else

Three principal types, because they are genuinely different:

- **Human** acts with their own authority
- **Agent** acts with a scoped, expiring subset of a human's authority, never more
- **Service** has its own identity and is still subject to policy, because "internal" is not a security boundary

`Scope` is passed by value. There is no method on it that widens it. That is what makes prompt injection containable: the attack has to change what the agent is permitted to do, and there is no code path that does.

The demo proves this rather than asserting it. It fingerprints the agent's authority, feeds it a live injection payload hidden in an invoice note, and prints the fingerprint again.

### Consequential actions freeze their arguments

A `Consequential` call produces a pending intent holding the validated arguments, a hash over them, a single-use token, a short expiry, and the sentence the human actually reads.

The summary is generated from validated arguments, never written by the model. A model that writes its own approval prompt can describe one action and request another.

### Three separate ceilings

Money, tokens and steps fail differently. The step ceiling is the one that catches a model retrying the same broken call four hundred times, which is the failure that actually happens.

Refused calls are charged. Otherwise an agent can probe the policy engine for free.

### The effect and the record can fail separately

An agent issues a refund. The money moves. The audit write fails. The process restarts.

Without explicit state the system either repeats the refund or forgets it. Here execution moves to `applied_unrecorded` before recording is attempted, and `Reconcile` finishes the job. Nothing is rolled back, because the effect was real and pretending otherwise would be a lie with financial consequences.

### The audit log is tamper-evident

Each entry carries the hash of the one before it. `Verify` returns the sequence number of the first entry that does not hold, because during an incident "broken from entry 41" is useful and "log invalid" is not.

Refusals are recorded, not just successes. A log that only shows what was permitted tells you nothing about what was attempted.

Secrets are redacted at write time.

## Layout

```
cmd/demo            seven scenarios, no API key
internal/tools      registry, typed schemas, validation
internal/policy     deny-by-default engine, principals, capability grants
internal/confirm    pending intents, argument freezing, single-use tokens
internal/budget     money, token and step ceilings
internal/audit      hash-chained append-only log with redaction
internal/untrusted  taint marking for anything a tool returns
internal/exec       idempotent execution and reconciliation
internal/gate       the one path a call takes
internal/billing    a fake billing system, so there is something real to refuse
typescript/         the confirmation core, ported, with cross-language hash parity
```

## TypeScript

Most AI tooling is TypeScript, so the piece most worth having in that stack is ported in [`typescript/`](typescript/): frozen-argument confirmation, single-use tokens, canonical hashing.

```
cd typescript
node --experimental-strip-types --test test/*.test.ts
```

Node 22.6 or newer, no build step, no dependencies.

Both implementations hash identical arguments to identical values, and both test suites assert the same fixtures, so neither can drift without a test failing. Making that true required matching one non-obvious behaviour: Go's `encoding/json` escapes `<`, `>` and `&` by default and `JSON.stringify` does not, so a naive port agrees on everything until an argument contains an ampersand.

## Tests

```
go test ./... -race
```

Named as attacks rather than as functions:

```
TestAgentCannotExecuteConsequentialActionDirectly
TestArgumentTamperingBetweenConfirmAndExecuteIsRejected
TestRetrievedContentCannotEscalatePermissions
TestConfirmationTokenIsSingleUse
TestConcurrentConfirmOnlyOneWins
TestBudgetCeilingStopsRunawayLoop
TestConcurrentChargesRespectTheCeiling
TestEffectSurvivesRecordingFailure
TestAuditChainDetectsTampering
TestRehashingAnEntryStillBreaksTheChain
TestUnknownFieldsAreRejected
TestMutatingTheCallersArgsDoesNotChangeTheIntent
```

## Honest limits

**The audit chain is tamper-evident, not tamper-proof.** There is no external anchor, so someone who can rewrite the whole log can rewrite the whole chain. What it prevents is partial editing, which is what covering something up actually looks like.

**Policy is in-process.** A real deployment wants a shared authorization service so that decisions are consistent across replicas.

**The injection scanner is not a defence.** It flags known phrasings, which is useful for alerting and for the demo. A payload avoiding those phrases is still contained, because the permission model does not depend on recognising the attack.

**No model provider is included.** A scripted driver runs the demo so the failure cases are reproducible. A real provider is an adapter, not a rewrite.

**Storage is in memory.** The interfaces are where a database goes.

## Why Go

Most agent tooling is Python. The parts of this problem that are hard, concurrency, timeouts, partial failure, are the parts Go is good at, and the race detector earns its place in a repo about correctness under concurrency.

The design is language-agnostic. Nothing here depends on Go specifically.

## Licence

MIT.
