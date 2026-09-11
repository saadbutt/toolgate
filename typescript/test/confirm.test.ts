import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { IntentStore, ConfirmError, confirmAndRun } from "../src/confirm.ts";
import type { Args } from "../src/canonical.ts";

const refund = (): Args => ({
  invoice_id: "INV-1002",
  amount_cents: 4200,
  reason: "duplicate charge",
});

function newStore(now?: () => Date) {
  return new IntentStore({ ttlMs: 60_000, now });
}

describe("confirmation", () => {
  test("confirm returns the frozen arguments", () => {
    const store = newStore();
    const { intent, token } = store.create("issue_refund", refund(), "refund $42", "agent-1", "saad");

    const got = store.confirm(intent.id, token, "saad");
    assert.equal(got.tool, "issue_refund");
    assert.equal(got.args.amount_cents, 4200);
  });

  test("mutating the caller's args does not change the intent", () => {
    // The aliasing bug: if the store kept the caller's object, an agent could
    // edit an approved action after it was approved.
    const store = newStore();
    const args = refund();
    const { intent, token } = store.create("issue_refund", args, "refund", "agent-1", "saad");

    args.amount_cents = 999_999;

    const got = store.confirm(intent.id, token, "saad");
    assert.equal(got.args.amount_cents, 4200);
  });

  test("mutating the returned args does not change the intent", () => {
    const store = newStore();
    const { intent } = store.create("issue_refund", refund(), "refund", "agent-1", "saad");
    const view = store.pending(intent.id);
    view.args.amount_cents = 1;
    assert.equal(store.pending(intent.id).args.amount_cents, 4200);
  });

  test("the token is single use", () => {
    const store = newStore();
    const { intent, token } = store.create("t", refund(), "", "a", "saad");
    store.confirm(intent.id, token, "saad");
    assert.throws(
      () => store.confirm(intent.id, token, "saad"),
      (e: unknown) => e instanceof ConfirmError && e.code === "already_used",
    );
  });

  test("a wrong token is rejected", () => {
    const store = newStore();
    const { intent } = store.create("t", refund(), "", "a", "saad");
    assert.throws(
      () => store.confirm(intent.id, "00".repeat(32), "saad"),
      (e: unknown) => e instanceof ConfirmError && e.code === "bad_token",
    );
  });

  test("a short token is rejected without throwing from timingSafeEqual", () => {
    const store = newStore();
    const { intent } = store.create("t", refund(), "", "a", "saad");
    assert.throws(
      () => store.confirm(intent.id, "abcd", "saad"),
      (e: unknown) => e instanceof ConfirmError && e.code === "bad_token",
    );
  });

  test("only the named approver can confirm", () => {
    const store = newStore();
    const { intent, token } = store.create("t", refund(), "", "agent-1", "saad");
    assert.throws(
      () => store.confirm(intent.id, token, "mallory"),
      (e: unknown) => e instanceof ConfirmError && e.code === "wrong_approver",
    );
  });

  test("an expired intent is rejected", () => {
    let now = new Date("2026-01-01T00:00:00Z");
    const store = newStore(() => now);
    const { intent, token } = store.create("t", refund(), "", "a", "saad");

    now = new Date(now.getTime() + 120_000);
    assert.throws(
      () => store.confirm(intent.id, token, "saad"),
      (e: unknown) => e instanceof ConfirmError && e.code === "expired",
    );
  });

  test("verifyArgs detects a one-cent change", () => {
    const store = newStore();
    const { intent } = store.create("t", refund(), "", "a", "saad");

    store.verifyArgs(intent.id, refund());
    assert.throws(
      () => store.verifyArgs(intent.id, { ...refund(), amount_cents: 4201 }),
      (e: unknown) => e instanceof ConfirmError && e.code === "args_mismatch",
    );
  });

  test("reading an intent does not reveal the token", () => {
    const store = newStore();
    const { intent } = store.create("t", refund(), "", "a", "saad");
    const view = store.pending(intent.id) as Record<string, unknown>;
    assert.equal(view.token, undefined);
    assert.equal(JSON.stringify(view).includes("token"), false);
  });

  test("reap removes expired intents", () => {
    let now = new Date("2026-01-01T00:00:00Z");
    const store = newStore(() => now);
    for (let i = 0; i < 3; i++) store.create("t", refund(), "", "a", "saad");

    now = new Date(now.getTime() + 120_000);
    assert.equal(store.reap(), 3);
  });

  test("confirmAndRun executes the frozen arguments, not supplied ones", async () => {
    const store = newStore();
    const { intent, token } = store.create("issue_refund", refund(), "refund $42", "agent-1", "saad");

    let executed = 0;
    const result = await confirmAndRun(store, intent.id, token, "saad", {
      issue_refund: (args) => {
        executed = args.amount_cents as number;
        return `refunded ${args.amount_cents}`;
      },
    });

    assert.equal(executed, 4200);
    assert.equal(result, "refunded 4200");
  });

  test("confirmAndRun cannot be replayed", async () => {
    const store = newStore();
    const { intent, token } = store.create("t", refund(), "", "a", "saad");
    const handlers = { t: () => "ok" };

    await confirmAndRun(store, intent.id, token, "saad", handlers);
    await assert.rejects(
      () => confirmAndRun(store, intent.id, token, "saad", handlers),
      (e: unknown) => e instanceof ConfirmError && e.code === "already_used",
    );
  });

  test("concurrent confirmations: only one wins", async () => {
    const store = newStore();
    const { intent, token } = store.create("t", refund(), "", "a", "saad");

    const attempts = Array.from({ length: 12 }, async () => {
      try {
        store.confirm(intent.id, token, "saad");
        return true;
      } catch {
        return false;
      }
    });
    const wins = (await Promise.all(attempts)).filter(Boolean).length;
    assert.equal(wins, 1);
  });
});
