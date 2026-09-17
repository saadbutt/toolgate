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
| 5 | Arguments swapped between approval and execution | The intent handed back is a copy. Execution takes no arguments and uses the frozen ones |
| 6 | Agent loops on a malformed call | Step ceiling, charged before the call is even validated |
| 7 | Audit log edited or cut short | Hash chain breaks and names the entry. A separately kept head catches deleted recent entries |

Scenario 5 is the one worth reading the code for. "Confirm before executing" is easy to implement wrongly: if you re-ask the model for arguments after approval, you approved a description and executed something else.

## Design

A model's call takes one path, in this order:

```
charge a step -> validate -> charge money -> decide -> execute -> record
```

Approving a pending intent takes the same kind of path:

```
charge a step -> check the approver is human -> consume the token -> decide again -> execute -> record
```

The gate has two ways in, `Submit` and `ConfirmAndRun`, and its collaborators are unexported, so neither way skips or reorders a step. Every interesting failure in agent systems comes from a step that was skipped once, for a good reason, in a hurry. This protects the path a model's output takes. The host program that registered the handlers can still call its own handlers directly.

### Arguments are validated before policy sees them

Model output is a request, not a fact. It is checked against a declared schema and refused if it does not match, rather than coerced into something plausible.

Unknown fields are rejected, not ignored. `10.7` cents is refused, not truncated. Errors name the field and the bound, so an agent can correct itself.

### Authority comes from the principal and nothing else

Three principal types, because they are genuinely different:

- **Human** acts with their own authority
- **Agent** acts with a scoped, expiring subset of a human's authority, never more
- **Service** has its own identity and is still subject to policy, because "internal" is not a security boundary

Authority comes from the `Principal` the host passes in, never from tool arguments or tool output. `Scope` is passed by value and has no method that widens it, and its tool set is immutable, so no copy of a grant can write back into the original. That is what makes prompt injection containable: the attack has to change what the agent is permitted to do, and nothing the model sends or reads reaches the scope.

The demo proves this rather than asserting it. It fingerprints the agent's authority, feeds it a live injection payload hidden in an invoice note, and prints the fingerprint again.

### Consequential actions freeze their arguments

A `Consequential` call produces a pending intent holding the validated arguments, a hash over them, a single-use token, a short expiry, and the sentence the human actually reads. The intent handed back to the caller is a copy, so editing it changes nothing that executes.

Approval is not a way around policy. The approver has to be a human, and an agent acting for no one gets no intent at all rather than approving its own. Policy runs again at approval time, for both the agent and the approver, so a grant that expired while the intent waited stops it. The gate only executes intents it created.

The summary is built by the gate from the validated arguments, with money formatted from the integer amount, not from prose the model wrote about the action. A model that writes its own approval prompt can describe one action and request another. String arguments such as `reason` are still model text and appear in the summary as they are.

### Three separate ceilings

Money, tokens and steps fail differently. The step ceiling is the one that catches a model retrying the same broken call four hundred times, which is the failure that actually happens.

Every call is charged a step when it arrives, before it is validated, so malformed calls count too. Money is charged once validated arguments say how much, before the policy decision, so a refund that is refused or never approved still counts. Otherwise an agent can probe the policy engine for free. Refusals of unvalidated input write a bounded copy of it to the audit log, so a model sending the same megabyte in a loop does not become a megabyte per entry.

### The effect and the record can fail separately

An agent issues a refund. The money moves. The audit write fails. The process restarts.

Without explicit state the system either repeats the refund or forgets it. Here execution moves to `applied_unrecorded` before recording is attempted. If the audit log's sink refuses the write, the call stays there, `Gate.Unrecorded` lists it, and `Gate.Reconcile` writes the record once storage is back, without running the effect again. Nothing is rolled back, because the effect was real and pretending otherwise would be a lie with financial consequences.

A handler that returns an error is saying nothing happened, so the same key can run again. A handler that panics is different: nobody knows whether the effect happened. The panic does not reach the caller, and the key is held rather than retried. `Gate.Unresolved` lists it, and `Gate.Resolve` records what someone found when they checked: applied, so repeats replay and `Reconcile` writes the record, or not applied, so the key can run again.

This state lives in memory. After a restart the executor no longer knows which keys ran, so neither idempotency nor reconciliation survives one.

### The audit log is tamper-evident

Each entry carries the hash of the one before it, and the log keeps a head: the entry count and the hash of the last entry. `VerifyChain` checks stored entries against a head kept somewhere else and returns the sequence number of the first entry that does not hold, because during an incident "broken from entry 41" is useful and "log invalid" is not. Deleting the most recent entries breaks no link, so without the head it would verify clean.

Refusals are recorded, not just successes. A log that only shows what was permitted tells you nothing about what was attempted.

Fields with common secret names are redacted at write time.

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

Both test suites pin the same fixture hashes, so a change to either encoder that affects one of those cases fails a test. Getting them to agree required matching two non-obvious behaviours, both places where Go's `encoding/json` escapes and `JSON.stringify` does not: `<`, `>` and `&`, which a naive port gets wrong as soon as an argument contains an ampersand, and the line and paragraph separators U+2028 and U+2029, which arrive in text pasted from PDFs. The first port missed the separators and the fixtures did not notice, so they are pinned now, along with non-ASCII text and control characters.

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
TestMutatingTheReturnedIntentDoesNotChangeTheStore
TestGrantExpiringBeforeConfirmationStopsExecution
TestAgentWithoutAHumanCannotBeItsOwnApprover
TestMalformedCallsAreNotFree
TestTruncatedLogIsDetected
TestEffectWhoseRecordFailedIsReconciled
TestReconcileWritesEachRecordOnce
TestFailedCallCanBeRetriedUnderSameKey
TestPanickingHandlerDoesNotWedgeItsKey
```

## Honest limits

**The audit chain is tamper-evident, not tamper-proof.** The head is only as safe as wherever it is kept. Someone who can rewrite both the log and its head can rewrite the whole chain. What it detects is partial editing and deleting recent entries, which is what covering something up actually looks like.

**Decision entries are best-effort when storage fails.** The executor's record of an effect is retried by `Reconcile`. The gate's own entries, for refusals, pending intents and outcomes, are not: if the sink refuses one, it is dropped.

**Policy is in-process.** A real deployment wants a shared authorization service so that decisions are consistent across replicas.

**The injection scanner is not a defence.** It flags known phrasings, which is useful for alerting and for the demo. A payload avoiding those phrases is still contained, because the permission model does not depend on recognising the attack.

**No model provider is included.** A scripted driver runs the demo so the failure cases are reproducible. A real provider is an adapter, not a rewrite.

**Storage is in memory.** The audit log takes a sink for durable writes. Intents, budgets and execution records have no storage hook yet, so none of them survive a restart.

**Idempotency is declared, not verified.** `Tool.Idempotent` is checked once, at registration. The gate's executor stops a repeated key from running twice within one process, but the demo billing system's `issue_refund` appends on every call and relies on that entirely.

**There are no timeouts.** The context is passed through to the handler, and nothing in the gate sets a deadline or checks for cancellation. A handler that never returns holds its key in flight for the life of the process.

## Why Go

Most agent tooling is Python. The parts of this problem that are hard, concurrency and partial failure, are the parts Go is good at, and the race detector earns its place in a repo about correctness under concurrency.

The design is language-agnostic. Nothing here depends on Go specifically.

## Licence

MIT.
