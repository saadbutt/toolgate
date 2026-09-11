/**
 * The confirmation core, demonstrated in about twenty lines of output.
 *
 *   node --experimental-strip-types src/demo.ts
 *
 * No dependencies, no API key, no build step.
 */

import { IntentStore, ConfirmError } from "./confirm.ts";
import { hashArgs, type Args } from "./canonical.ts";

const store = new IntentStore({ ttlMs: 60_000 });

let refunded = 0;
const handlers: Record<string, (args: Args) => string> = {
  issue_refund(args) {
    refunded += args.amount_cents as number;
    return `refunded ${money(args.amount_cents as number)} against ${args.invoice_id}`;
  },
};

const line = "=".repeat(64);
const money = (c: number) => `$${Math.floor(c / 100)}.${String(c % 100).padStart(2, "0")}`;

console.log(`\n${line}\nThe agent asks to refund $42.00\n${line}`);

const requested: Args = {
  invoice_id: "INV-1002",
  amount_cents: 4200,
  reason: "duplicate charge",
};
const { intent, token } = store.create(
  "issue_refund",
  requested,
  `Issue a refund | invoice_id: ${requested.invoice_id} | amount: ${money(4200)}`,
  "agent-1",
  "saad",
);

console.log(`  nothing executed. intent ${intent.id.slice(0, 8)} awaits ${intent.approver}`);
console.log(`  human sees: ${intent.summary}`);
console.log(`  args hash:  ${intent.argsHash.slice(0, 16)}`);
console.log(`  refunded so far: ${money(refunded)}`);

console.log(`\n${line}\nThe amount is swapped to $4,200.00 after approval\n${line}`);

const tampered: Args = { ...requested, amount_cents: 420_000 };
console.log(`  tampered hash: ${hashArgs(tampered).slice(0, 16)}`);
try {
  store.verifyArgs(intent.id, tampered);
  console.log("  NOT DETECTED, which would be a bug");
  process.exit(1);
} catch (e) {
  console.log(`  rejected: ${(e as ConfirmError).message}`);
}

console.log(`\n${line}\nSaad approves\n${line}`);

const { tool, args } = store.confirm(intent.id, token, "saad");
const handler = handlers[tool];
if (!handler) {
  throw new Error(`confirmAndRun: no handler registered for ${tool}`);
}
console.log(`  ${handler(args)}`);
console.log(`  executed the approved amount, not the swapped one`);

console.log(`\n${line}\nThe same token is presented again\n${line}`);

try {
  store.confirm(intent.id, token, "saad");
  console.log("  REPLAY ACCEPTED, which would be a bug");
  process.exit(1);
} catch (e) {
  console.log(`  rejected: ${(e as ConfirmError).message}`);
}

console.log(`\n  total refunded: ${money(refunded)}\n`);
console.log("Execution never takes arguments. It only takes a token,");
console.log("and the arguments come from the copy frozen at approval time.\n");
