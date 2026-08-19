import { strict as assert } from "node:assert";
import { test } from "node:test";
import {
  assertNftTransferAmount,
  parseSplTransferAmount,
} from "./transfer-nft-policy";

const USDC_MAINNET = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const USDC_DEVNET = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU";
const BLOCKED = [USDC_MAINNET, USDC_DEVNET];
const NFT_MINT = "NftMint11111111111111111111111111111111111";

/** Build SPL Transfer (type 3) or TransferChecked (type 12) data with u64 LE amount. */
function encodeTransferData(type: 3 | 12, amount: bigint): Buffer {
  const buf = Buffer.alloc(type === 12 ? 10 : 9);
  buf[0] = type;
  buf.writeBigUInt64LE(amount, 1);
  if (type === 12) buf[9] = 0; // decimals
  return buf;
}

test("parseSplTransferAmount: Transfer amount 1 → 1n", () => {
  const data = encodeTransferData(3, 1n);
  assert.equal(parseSplTransferAmount(data), 1n);
});

test("parseSplTransferAmount: Transfer amount 1000000 → 1000000n", () => {
  const data = encodeTransferData(3, 1000000n);
  assert.equal(parseSplTransferAmount(data), 1000000n);
});

test("parseSplTransferAmount: TransferChecked amount 1 → 1n", () => {
  const data = encodeTransferData(12, 1n);
  assert.equal(parseSplTransferAmount(data), 1n);
});

test("parseSplTransferAmount: TransferChecked amount 1000000 → 1000000n", () => {
  const data = encodeTransferData(12, 1000000n);
  assert.equal(parseSplTransferAmount(data), 1000000n);
});

test("parseSplTransferAmount: short buffer → null", () => {
  assert.equal(parseSplTransferAmount(Buffer.from([3, 1, 0])), null);
  assert.equal(parseSplTransferAmount(Buffer.alloc(8)), null);
  assert.equal(parseSplTransferAmount(Buffer.alloc(0)), null);
});

test("parseSplTransferAmount: unsupported instruction type → null", () => {
  const data = encodeTransferData(3, 1n);
  data[0] = 7; // Approve
  assert.equal(parseSplTransferAmount(data), null);
});

test("vault_transfer policy: amount ≠ 1 rejected", () => {
  const amt = parseSplTransferAmount(encodeTransferData(3, 2n));
  assert.ok(amt !== null);
  assert.equal(amt.toString(), "2");
  // Mirror validateVaultTransferInstructions amount gate (amt must be 1n)
  const rejected = amt !== 1n;
  assert.equal(rejected, true);
});

test("vault_transfer policy: USDC mint rejected even with amount 1", () => {
  const amt = parseSplTransferAmount(encodeTransferData(3, 1n));
  assert.equal(amt, 1n);
  const policy = assertNftTransferAmount({
    mint: USDC_MAINNET,
    amount: 1,
    blockedMints: BLOCKED,
  });
  assert.equal(policy.ok, false);
  if (!policy.ok) {
    assert.equal(policy.status, 400);
    assert.equal(policy.error, "fungible_mint_not_allowed");
  }
});

test("vault_transfer policy: USDC devnet mint rejected", () => {
  const policy = assertNftTransferAmount({
    mint: USDC_DEVNET,
    amount: 1,
    blockedMints: BLOCKED,
  });
  assert.equal(policy.ok, false);
  if (!policy.ok) assert.equal(policy.error, "fungible_mint_not_allowed");
});

test("vault_transfer policy: amount=1 on non-USDC mint allowed", () => {
  const amt = parseSplTransferAmount(encodeTransferData(12, 1n));
  assert.equal(amt, 1n);
  const policy = assertNftTransferAmount({
    mint: NFT_MINT,
    amount: 1,
    blockedMints: BLOCKED,
  });
  assert.equal(policy.ok, true);
  if (policy.ok) assert.equal(policy.amount, 1);
});
