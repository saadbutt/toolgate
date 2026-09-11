import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { canonicalize, hashArgs, type Args } from "../src/canonical.ts";

describe("canonical encoding", () => {
  // These are the same fixtures asserted in internal/confirm/canonical_test.go.
  // If either implementation drifts, one of the two suites fails.
  const goFixtures: Array<{ name: string; args: Args; hash: string }> = [
    {
      name: "typical refund",
      args: { invoice_id: "INV-1002", amount_cents: 4200, reason: "duplicate charge" },
      hash: "a8c23bbb2d44e3752e9390e4dfdd45e22985e0893b77c6d57275f96ed4fd5cf6",
    },
    {
      name: "key order must not matter",
      args: { z: "last", a: "first", m: 5 },
      hash: "39a0ebe20e535c8de316cc4c3b67ed0af35b8a179f1bba5d35685fe6e0815b20",
    },
    {
      name: "html-escaped characters",
      args: { note: "a<b && c>d", n: 1 },
      hash: "52e75a7c673c4be58a0dd6683045abdf3ffe300544c374ac683e178da1a0fe46",
    },
    {
      name: "booleans and empty strings",
      args: { flag: true, empty: "" },
      hash: "d726b9c4e59b06b8918a6d61ed472b5cef8bb797aaa99c3d3b4d8dc428b7f852",
    },
  ];

  for (const f of goFixtures) {
    test(`matches the Go implementation: ${f.name}`, () => {
      assert.equal(hashArgs(f.args), f.hash);
    });
  }

  test("insertion order does not change the encoding", () => {
    const a: Args = { z: "last", a: "first", m: 5 };
    const b: Args = { m: 5, a: "first", z: "last" };
    assert.equal(canonicalize(a), canonicalize(b));
    assert.equal(hashArgs(a), hashArgs(b));
  });

  test("escapes the characters Go escapes", () => {
    // The difference that silently breaks a naive port. JSON.stringify leaves
    // these alone; Go does not.
    assert.equal(canonicalize({ s: "a<b&c>d" }), '{"s":"a\\u003cb\\u0026c\\u003ed"}');
  });

  test("emits no whitespace", () => {
    const out = canonicalize({ a: 1, b: "two", c: true });
    assert.ok(!/\s/.test(out), `found whitespace in ${out}`);
  });

  test("one cent of difference changes the hash", () => {
    const a = hashArgs({ amount_cents: 4200 });
    const b = hashArgs({ amount_cents: 4201 });
    assert.notEqual(a, b);
  });

  test("rejects fractional numbers rather than rounding", () => {
    assert.throws(() => canonicalize({ amount_cents: 10.7 }), TypeError);
  });

  test("rejects integers beyond the safe range", () => {
    // Past 2^53 a JS number cannot represent every int64, so the two
    // implementations would stop agreeing. Failing loudly beats diverging.
    assert.throws(() => canonicalize({ n: Number.MAX_SAFE_INTEGER + 2 }), RangeError);
  });

  test("rejects unsupported types", () => {
    assert.throws(() => canonicalize({ x: null as unknown as string }), TypeError);
    assert.throws(() => canonicalize({ x: undefined as unknown as string }), TypeError);
    assert.throws(() => canonicalize({ x: {} as unknown as string }), TypeError);
  });
});
