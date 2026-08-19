import { strict as assert } from "node:assert";
import { test } from "node:test";
import {
  encodeSafeTransferFrom,
  parseEvmNftTokenId,
} from "./evm-nft-transfer";

const FROM = "0x1111111111111111111111111111111111111111";
const TO = "0x2222222222222222222222222222222222222222";

test("encodeSafeTransferFrom uses 3-arg selector 0x42842e0e", () => {
  const data = encodeSafeTransferFrom(FROM, TO, 1n);
  assert.equal(data.slice(0, 10).toLowerCase(), "0x42842e0e");
  assert.ok(data.length > 10);
});

test("encodeSafeTransferFrom is not solidityPacked-without-selector", () => {
  const data = encodeSafeTransferFrom(FROM, TO, 1n);
  // Packed addresses would start with 0x + 40 hex chars of address, not a selector
  assert.notEqual(data.slice(0, 42).toLowerCase(), FROM.toLowerCase());
  assert.ok(data.startsWith("0x42842e0e"));
});

test("parseEvmNftTokenId accepts number 0 and 1", () => {
  assert.deepEqual(parseEvmNftTokenId(0), { ok: true, tokenId: 0n });
  assert.deepEqual(parseEvmNftTokenId(1), { ok: true, tokenId: 1n });
});

test("parseEvmNftTokenId accepts string and bigint", () => {
  assert.deepEqual(parseEvmNftTokenId("42"), { ok: true, tokenId: 42n });
  assert.deepEqual(parseEvmNftTokenId(99n), { ok: true, tokenId: 99n });
});

test("parseEvmNftTokenId rejects missing", () => {
  const r = parseEvmNftTokenId(undefined);
  assert.equal(r.ok, false);
  if (!r.ok) assert.match(r.error, /tokenId is required/);
});

test("parseEvmNftTokenId rejects negative and fractional", () => {
  assert.equal(parseEvmNftTokenId(-1).ok, false);
  assert.equal(parseEvmNftTokenId(1.5).ok, false);
  assert.equal(parseEvmNftTokenId("-1").ok, false);
  assert.equal(parseEvmNftTokenId("1.0").ok, false);
});
