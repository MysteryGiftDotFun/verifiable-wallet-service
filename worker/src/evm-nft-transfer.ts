/**
 * Helpers for EVM ERC-721 transfers on POST /transfer-nft (Base / Robinhood).
 */
import { ethers } from "ethers";

export const ERC721_SAFE_TRANSFER_FROM_ABI = [
  "function safeTransferFrom(address from, address to, uint256 tokenId) external",
] as const;

export type ParseTokenIdResult =
  | { ok: true; tokenId: bigint }
  | { ok: false; error: string };

/**
 * Require a non-negative integer tokenId from the HTTP body.
 * Accepts number | string | bigint; rejects missing/fractional/negative values.
 */
export function parseEvmNftTokenId(raw: unknown): ParseTokenIdResult {
  if (raw === undefined || raw === null || raw === "") {
    return {
      ok: false,
      error: "tokenId is required for EVM NFT transfers",
    };
  }
  if (typeof raw === "bigint") {
    if (raw < 0n) {
      return { ok: false, error: "tokenId must be a non-negative integer" };
    }
    return { ok: true, tokenId: raw };
  }
  if (typeof raw === "number") {
    if (!Number.isInteger(raw) || raw < 0 || !Number.isSafeInteger(raw)) {
      return { ok: false, error: "tokenId must be a non-negative integer" };
    }
    return { ok: true, tokenId: BigInt(raw) };
  }
  if (typeof raw === "string") {
    const s = raw.trim();
    if (!/^\d+$/.test(s)) {
      return { ok: false, error: "tokenId must be a non-negative integer" };
    }
    return { ok: true, tokenId: BigInt(s) };
  }
  return { ok: false, error: "tokenId must be a non-negative integer" };
}

/** Encode 3-arg safeTransferFrom calldata (selector 0x42842e0e). */
export function encodeSafeTransferFrom(
  from: string,
  to: string,
  tokenId: bigint,
): string {
  const iface = new ethers.Interface([...ERC721_SAFE_TRANSFER_FROM_ABI]);
  return iface.encodeFunctionData("safeTransferFrom", [from, to, tokenId]);
}
