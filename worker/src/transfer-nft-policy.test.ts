import { strict as assert } from "node:assert";
import { test } from "node:test";
import { assertNftTransferAmount } from "./transfer-nft-policy";

const BLOCKED = [
  "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
  "0x833589fCD6eDb6E08f4c7c32D4f288B37C9CAA8",
];
const NFT_MINT = "NftMint11111111111111111111111111111111111";

test("omitted amount defaults to 1", () => {
  const result = assertNftTransferAmount({
    mint: NFT_MINT,
    amount: undefined,
    blockedMints: BLOCKED,
  });
  assert.equal(result.ok, true);
  if (result.ok) assert.equal(result.amount, 1);
});

test("null amount defaults to 1", () => {
  const result = assertNftTransferAmount({
    mint: NFT_MINT,
    amount: null,
    blockedMints: BLOCKED,
  });
  assert.equal(result.ok, true);
  if (result.ok) assert.equal(result.amount, 1);
});

test("amount 1 is accepted", () => {
  const result = assertNftTransferAmount({
    mint: NFT_MINT,
    amount: 1,
    blockedMints: BLOCKED,
  });
  assert.equal(result.ok, true);
  if (result.ok) assert.equal(result.amount, 1);
});

test('amount "1" is accepted', () => {
  const result = assertNftTransferAmount({
    mint: NFT_MINT,
    amount: "1",
    blockedMints: BLOCKED,
  });
  assert.equal(result.ok, true);
  if (result.ok) assert.equal(result.amount, 1);
});

test("amount 2 is rejected", () => {
  const result = assertNftTransferAmount({
    mint: NFT_MINT,
    amount: 2,
    blockedMints: BLOCKED,
  });
  assert.equal(result.ok, false);
  if (!result.ok) {
    assert.equal(result.status, 400);
    assert.equal(result.error, "nft_amount_must_be_1");
  }
});

test("amount 0 is rejected", () => {
  const result = assertNftTransferAmount({
    mint: NFT_MINT,
    amount: 0,
    blockedMints: BLOCKED,
  });
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.error, "nft_amount_must_be_1");
});

test("amount -1 is rejected", () => {
  const result = assertNftTransferAmount({
    mint: NFT_MINT,
    amount: -1,
    blockedMints: BLOCKED,
  });
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.error, "nft_amount_must_be_1");
});

test("amount 1000000 is rejected", () => {
  const result = assertNftTransferAmount({
    mint: NFT_MINT,
    amount: 1000000,
    blockedMints: BLOCKED,
  });
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.error, "nft_amount_must_be_1");
});

test("blocked mint any case is rejected", () => {
  const result = assertNftTransferAmount({
    mint: BLOCKED[0].toLowerCase(),
    amount: 1,
    blockedMints: BLOCKED,
  });
  assert.equal(result.ok, false);
  if (!result.ok) {
    assert.equal(result.status, 400);
    assert.equal(result.error, "fungible_mint_not_allowed");
  }
});

test("blocked EVM mint uppercase is rejected", () => {
  const result = assertNftTransferAmount({
    mint: BLOCKED[1].toUpperCase(),
    amount: undefined,
    blockedMints: BLOCKED,
  });
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.error, "fungible_mint_not_allowed");
});

test("unblocked mint with amount 1 succeeds", () => {
  const result = assertNftTransferAmount({
    mint: NFT_MINT,
    amount: 1,
    blockedMints: BLOCKED,
  });
  assert.equal(result.ok, true);
  if (result.ok) assert.equal(result.amount, 1);
});
