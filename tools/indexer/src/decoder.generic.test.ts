/**
 * Tests for decoder.ts — verifies event decoding logic for each event type.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { decodeEvent } from "./decoder.js";
import type { RawSorobanEvent } from "./rpc.js";

/**
 * Helper to create a minimal RawSorobanEvent for testing.
 * Real events have base64-encoded XDR in topic/value fields.
 */
function makeRawEvent(
  topic: string[],
  value: string,
  contractId = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4"
): RawSorobanEvent {
  return {
    type: "contract",
    ledger: 12345,
    ledgerClosedAt: "2024-01-15T10:00:00Z",
    contractId,
    id: "0-1",
    pagingToken: "0-1",
    topic,
    value,
    inSuccessfulContractCall: true,
  };
}

/**
 * Manually crafted XDR blobs for testing.
 * These are minimal valid XDR ScVal encodings.
 */
function xdrU32(value: number): number[] {
  return [(value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff];
}

function xdrSymbol(value: string): string {
  const bytes = new TextEncoder().encode(value);
  const padding = (4 - (bytes.length % 4)) % 4;
  return Buffer.from([
    ...xdrU32(15), ...xdrU32(bytes.length), ...bytes, ...new Array(padding).fill(0),
  ]).toString("base64");
}

function xdrMapField(key: string, encodedValue: string): string {
  return Buffer.concat([
    Buffer.from([...xdrU32(17), ...xdrU32(1), ...xdrU32(1)]),
    Buffer.from(xdrSymbol(key), "base64"),
    Buffer.from(encodedValue, "base64"),
  ]).toString("base64");
}

const XDR_SYMBOL_ALLOWADD = xdrSymbol("allow_add");
const XDR_SYMBOL_ALLOWREMOVE = xdrSymbol("allow_remove");
const XDR_SYMBOL_DENYADD = xdrSymbol("deny_add");
const XDR_SYMBOL_DENYREMOVE = xdrSymbol("deny_remove");
const XDR_SYMBOL_BLOCKED = xdrSymbol("blocked");
const XDR_SYMBOL_JURISDICTIONSET = xdrSymbol("jurisdiction_set");

// Sample G-address (account): 32 zero-byte ED25519 public key
const XDR_ADDRESS_ACCOUNT =
  "AAAAEgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

// Sample contract address (32 zero bytes)
const XDR_ADDRESS_CONTRACT =
  "AAAAEgAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

const XDR_VOID = "AAAAAQ=="; // ScVal::Void
const XDR_STRING_US = "AAAADgAAAAJVUwAA"; // ScVal::String("US")
const XDR_I128_100 = "AAAACgAAAAAAAAAAAAAAAAAAAGQ="; // ScVal::I128(100)
const XDR_MAP_AMOUNT_100 = xdrMapField("amount", XDR_I128_100);
const XDR_MAP_CODE_US = xdrMapField("code", XDR_STRING_US);

test("decodeEvent: AllowAdd", () => {
  const raw = makeRawEvent(
    [XDR_SYMBOL_ALLOWADD, XDR_ADDRESS_ACCOUNT],
    XDR_VOID
  );
  const decoded = decodeEvent(raw);
  assert.ok(decoded);
  assert.equal(decoded.eventType, "AllowAdd");
  assert.equal(decoded.contractId, raw.contractId);
  assert.equal(decoded.ledgerSequence, 12345);
  assert.ok(decoded.address?.startsWith("G"));
  assert.equal(decoded.addressTo, null);
  assert.equal(decoded.amount, null);
  assert.equal(decoded.jurisdiction, null);
});

test("decodeEvent: AllowRemove", () => {
  const raw = makeRawEvent(
    [XDR_SYMBOL_ALLOWREMOVE, XDR_ADDRESS_ACCOUNT],
    XDR_VOID
  );
  const decoded = decodeEvent(raw);
  assert.ok(decoded);
  assert.equal(decoded.eventType, "AllowRemove");
  assert.ok(decoded.address?.startsWith("G"));
});

test("decodeEvent: DenyAdd", () => {
  const raw = makeRawEvent([XDR_SYMBOL_DENYADD, XDR_ADDRESS_ACCOUNT], XDR_VOID);
  const decoded = decodeEvent(raw);
  assert.ok(decoded);
  assert.equal(decoded.eventType, "DenyAdd");
  assert.ok(decoded.address?.startsWith("G"));
});

test("decodeEvent: DenyRemove", () => {
  const raw = makeRawEvent(
    [XDR_SYMBOL_DENYREMOVE, XDR_ADDRESS_ACCOUNT],
    XDR_VOID
  );
  const decoded = decodeEvent(raw);
  assert.ok(decoded);
  assert.equal(decoded.eventType, "DenyRemove");
  assert.ok(decoded.address?.startsWith("G"));
});

test("decodeEvent: Blocked", () => {
  const raw = makeRawEvent(
    [XDR_SYMBOL_BLOCKED, XDR_ADDRESS_ACCOUNT, XDR_ADDRESS_ACCOUNT],
    XDR_MAP_AMOUNT_100
  );
  const decoded = decodeEvent(raw);
  assert.ok(decoded);
  assert.equal(decoded.eventType, "Blocked");
  assert.ok(decoded.address?.startsWith("G"));
  assert.ok(decoded.addressTo?.startsWith("G"));
  assert.equal(decoded.amount, "100");
});

test("decodeEvent: JurisdictionSet", () => {
  const raw = makeRawEvent(
    [XDR_SYMBOL_JURISDICTIONSET, XDR_ADDRESS_ACCOUNT],
    XDR_MAP_CODE_US
  );
  const decoded = decodeEvent(raw);
  assert.ok(decoded);
  assert.equal(decoded.eventType, "JurisdictionSet");
  assert.ok(decoded.address?.startsWith("G"));
  assert.equal(decoded.jurisdiction, "US");
});

test("decodeEvent: contract address", () => {
  const raw = makeRawEvent(
    [XDR_SYMBOL_DENYADD, XDR_ADDRESS_CONTRACT],
    XDR_VOID
  );
  const decoded = decodeEvent(raw);
  assert.ok(decoded);
  assert.equal(decoded.eventType, "DenyAdd");
  // Contract addresses are hex-encoded, 64 chars (32 bytes * 2)
  assert.equal(decoded.address?.length, 64);
  assert.match(decoded.address!, /^[0-9a-f]{64}$/);
});

test("decodeEvent: unknown event type returns null", () => {
  const XDR_SYMBOL_UNKNOWN = "AAAAD1Vua25vd25FdmVudAA="; // Symbol("UnknownEvent")
  const raw = makeRawEvent(
    [XDR_SYMBOL_UNKNOWN, XDR_ADDRESS_ACCOUNT],
    XDR_VOID
  );
  const decoded = decodeEvent(raw);
  assert.equal(decoded, null);
});

test("decodeEvent: malformed event returns null", () => {
  const raw = makeRawEvent([], XDR_VOID);
  const decoded = decodeEvent(raw);
  assert.equal(decoded, null);
});

test("decodeEvent: invalid base64 returns null", () => {
  const raw = makeRawEvent(["INVALID_BASE64!!!"], XDR_VOID);
  const decoded = decodeEvent(raw);
  assert.equal(decoded, null);
});
