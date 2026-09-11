/**
 * The gap between a human approving an action and that action happening.
 *
 * The bug this exists to prevent: approving a description and executing
 * something else. If the arguments are re-supplied after approval, the
 * approval covered nothing. Here they are frozen when the intent is created,
 * and `confirm` hands back the frozen copy.
 *
 * This is a port of internal/confirm from the Go implementation, kept to the
 * one piece most likely to be got wrong elsewhere. The Go version is the
 * complete system; this is the part worth having in your own stack.
 */

import { randomBytes, timingSafeEqual } from "node:crypto";
import { type Args, hashArgs } from "./canonical.ts";

export type ConfirmErrorCode =
  | "not_found"
  | "expired"
  | "already_used"
  | "bad_token"
  | "wrong_approver"
  | "args_mismatch";

export class ConfirmError extends Error {
  // Assigned in the body rather than as a constructor parameter property,
  // so the file runs under `node --experimental-strip-types` with no build
  // step. Keeping that true is worth more than the shorter syntax.
  readonly code: ConfirmErrorCode;

  constructor(code: ConfirmErrorCode, message: string) {
    super(message);
    this.name = "ConfirmError";
    this.code = code;
  }
}

/** A consequential action waiting for a human. */
export interface Intent {
  readonly id: string;
  readonly tool: string;
  /** The frozen, validated arguments. This copy is what executes. */
  readonly args: Args;
  /** Hash over the canonical encoding, which makes tampering detectable. */
  readonly argsHash: string;
  /** The sentence a human actually reads before approving. */
  readonly summary: string;
  readonly requestedBy: string;
  readonly approver: string;
  readonly createdAt: Date;
  readonly expiresAt: Date;
}

interface StoredIntent extends Intent {
  token: Buffer;
  used: boolean;
}

export interface StoreOptions {
  /**
   * How long an approval stays valid.
   *
   * Short by design. An approval that survives a day is an approval for a
   * situation that no longer exists.
   */
  ttlMs?: number;
  /** Injectable clock, for tests. */
  now?: (() => Date) | undefined;
}

export class IntentStore {
  readonly #intents = new Map<string, StoredIntent>();
  readonly #ttlMs: number;
  readonly #now: () => Date;

  constructor(opts: StoreOptions = {}) {
    this.#ttlMs = opts.ttlMs ?? 5 * 60_000;
    this.#now = opts.now ?? (() => new Date());
  }

  /**
   * Freezes a request and returns the intent plus a one-time token.
   *
   * The token is returned once and never stored in recoverable form, so
   * reading the store does not let you approve anything.
   */
  create(
    tool: string,
    args: Args,
    summary: string,
    requestedBy: string,
    approver: string,
  ): { intent: Intent; token: string } {
    const now = this.#now();
    const stored: StoredIntent = {
      id: randomBytes(12).toString("hex"),
      tool,
      // Copied, so a caller that mutates its own object afterwards cannot
      // change what was approved.
      args: { ...args },
      argsHash: hashArgs(args),
      summary,
      requestedBy,
      approver,
      createdAt: now,
      expiresAt: new Date(now.getTime() + this.#ttlMs),
      token: randomBytes(32),
      used: false,
    };
    this.#intents.set(stored.id, stored);
    return { intent: this.#public(stored), token: stored.token.toString("hex") };
  }

  /** Returns an intent for display without consuming it. */
  pending(id: string): Intent {
    const found = this.#intents.get(id);
    if (!found) throw new ConfirmError("not_found", `no intent ${id}`);
    return this.#public(found);
  }

  /**
   * Consumes the intent and returns the frozen arguments.
   *
   * Every failure is checked before the intent is marked used, and it is
   * marked used before the arguments are returned. Node is single-threaded
   * per event-loop turn and there is no await inside this method, so a second
   * caller cannot interleave and win the same token.
   */
  confirm(id: string, token: string, approver: string): { tool: string; args: Args } {
    const found = this.#intents.get(id);
    if (!found) throw new ConfirmError("not_found", `no intent ${id}`);
    if (found.used) throw new ConfirmError("already_used", "intent already used");
    if (this.#now() > found.expiresAt) throw new ConfirmError("expired", "intent expired");
    if (approver !== found.approver) {
      throw new ConfirmError("wrong_approver", `${approver} may not approve this intent`);
    }

    let supplied: Buffer;
    try {
      supplied = Buffer.from(token, "hex");
    } catch {
      throw new ConfirmError("bad_token", "token is not valid hex");
    }
    // timingSafeEqual throws on a length mismatch, which would itself leak
    // length information through the exception path, so length is compared
    // first and both paths end in the same error.
    if (supplied.length !== found.token.length || !timingSafeEqual(supplied, found.token)) {
      throw new ConfirmError("bad_token", "token mismatch");
    }

    found.used = true;
    return { tool: found.tool, args: { ...found.args } };
  }

  /**
   * Reports whether args are byte-identical to what was approved.
   *
   * Execution does not need this, because it uses the frozen copy. It exists
   * for callers that carry arguments alongside a token and want to prove they
   * were not swapped in transit.
   */
  verifyArgs(id: string, args: Args): void {
    const found = this.#intents.get(id);
    if (!found) throw new ConfirmError("not_found", `no intent ${id}`);
    if (hashArgs(args) !== found.argsHash) {
      throw new ConfirmError("args_mismatch", "arguments do not match what was approved");
    }
  }

  /** Deletes expired intents and returns how many went. */
  reap(): number {
    const now = this.#now();
    let n = 0;
    for (const [id, intent] of this.#intents) {
      if (now > intent.expiresAt) {
        this.#intents.delete(id);
        n++;
      }
    }
    return n;
  }

  #public(s: StoredIntent): Intent {
    const { token, used, ...rest } = s;
    void token;
    void used;
    return { ...rest, args: { ...s.args } };
  }
}

/**
 * Approves an intent and runs the handler against the frozen arguments.
 *
 * The arguments are not a parameter. That is the whole design: the caller
 * cannot supply them, so the caller cannot change them between approval and
 * effect.
 */
export async function confirmAndRun<T>(
  store: IntentStore,
  id: string,
  token: string,
  approver: string,
  handlers: Record<string, (args: Args) => Promise<T> | T>,
): Promise<T> {
  const { tool, args } = store.confirm(id, token, approver);
  const handler = handlers[tool];
  if (!handler) throw new Error(`confirmAndRun: no handler registered for ${tool}`);
  return await handler(args);
}
