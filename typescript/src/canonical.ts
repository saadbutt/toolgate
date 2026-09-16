/**
 * Canonical argument encoding and hashing.
 *
 * The confirmation check is only meaningful if the same arguments always
 * produce the same bytes. If two encodings of one value could differ, a
 * legitimate approval would occasionally fail, someone would disable the
 * check, and the whole mechanism would be decorative.
 *
 * This file deliberately matches Go's `encoding/json` output, including the
 * parts of it that are surprising, so that the Go implementation in this repo
 * and this one agree on every hash. The fixtures in test/canonical.test.ts
 * are the same ones asserted in internal/confirm/canonical_test.go.
 */

import { createHash } from "node:crypto";

/** The value types tool arguments may hold. Deliberately small. */
export type ArgValue = string | number | boolean;

/** A validated set of tool arguments. */
export type Args = Record<string, ArgValue>;

/**
 * Encodes args the way Go's encoding/json does for a map[string]any.
 *
 * Four behaviours have to match exactly:
 *
 *  1. Object keys are sorted. Go sorts map keys; JavaScript preserves
 *     insertion order, so sorting has to be explicit here.
 *  2. No whitespace between tokens.
 *  3. `<`, `>` and `&` are escaped to \u003c, \u003e and \u0026. Go does
 *     this by default to keep output safe to embed in HTML. JSON.stringify
 *     does not, and this is the difference that silently breaks a naive port:
 *     everything agrees until an argument contains an ampersand.
 *  4. U+2028 and U+2029, the line and paragraph separators, are escaped to
 *     \u2028 and \u2029. Go always does this; JSON.stringify emits them raw.
 *     They arrive in ordinary text pasted from PDFs and web pages.
 *
 * Everything else JSON.stringify already writes the way Go does: control
 * characters, quotes and backslashes are escaped identically, and all other
 * well-formed non-ASCII text is raw UTF-8. The pinned fixtures cover each case.
 */
export function canonicalize(args: Args): string {
  const keys = Object.keys(args).sort();
  const parts = keys.map((k) => {
    const value = args[k];
    if (value === undefined) {
      throw new TypeError(`canonicalize: ${k} has unsupported type undefined`);
    }
    return `${encodeString(k)}:${encodeValue(value, k)}`;
  });
  return `{${parts.join(",")}}`;
}

function encodeValue(v: ArgValue, key: string): string {
  switch (typeof v) {
    case "string":
      return encodeString(v);
    case "boolean":
      return v ? "true" : "false";
    case "number":
      if (!Number.isFinite(v)) {
        throw new TypeError(`canonicalize: ${key} is not a finite number`);
      }
      if (!Number.isInteger(v)) {
        // Refused rather than rounded, for the same reason the Go tools
        // package refuses fractional money: quietly turning 10.7 into 10 is
        // the kind of helpfulness that loses money.
        throw new TypeError(`canonicalize: ${key} must be a whole number, got ${v}`);
      }
      if (!Number.isSafeInteger(v)) {
        // Beyond 2^53 a JavaScript number cannot represent every integer a
        // Go int64 can, so the two implementations would stop agreeing.
        // Better to fail loudly at the boundary than to hash different values.
        throw new RangeError(`canonicalize: ${key} exceeds safe integer range`);
      }
      return String(v);
    default:
      throw new TypeError(`canonicalize: ${key} has unsupported type ${typeof v}`);
  }
}

const goEscapes: Record<string, string> = {
  "<": "\\u003c",
  ">": "\\u003e",
  "&": "\\u0026",
  "\u2028": "\\u2028",
  "\u2029": "\\u2029",
};

function encodeString(s: string): string {
  return JSON.stringify(s).replace(/[<>&\u2028\u2029]/g, (c) => goEscapes[c] ?? c);
}

/** Returns the hex sha256 of the canonical encoding of args. */
export function hashArgs(args: Args): string {
  return createHash("sha256").update(canonicalize(args), "utf8").digest("hex");
}
