/**
 * Policy for POST /transfer-nft: amount must be 1; known fungible mints blocked.
 * Callers pass blockedMints (USDC/USDG) so tests can inject fixtures.
 *
 * Also used by vault_transfer on POST /sign-transaction after parsing SPL
 * Transfer / TransferChecked instruction data.
 */

export type NftTransferDecision =
  | { ok: true; amount: 1 }
  | { ok: false; status: 400; error: string };

/**
 * Parse SPL Token Transfer (3) or TransferChecked (12) amount.
 * Layout: byte0 = instruction type, bytes 1–8 = u64 little-endian amount.
 * Returns null for short buffers or unsupported instruction types.
 */
export function parseSplTransferAmount(data: Uint8Array): bigint | null {
  if (data.length < 9) return null;
  const type = data[0];
  if (type !== 3 && type !== 12) return null;
  // u64 LE at offset 1
  const view = Buffer.from(data.buffer, data.byteOffset, data.byteLength);
  return view.readBigUInt64LE(1);
}

export function assertNftTransferAmount(args: {
  mint: string;
  amount: unknown;
  blockedMints: Iterable<string>;
}): NftTransferDecision {
  const blocked = new Set(
    [...args.blockedMints].map((m) => m.toLowerCase()),
  );
  if (blocked.has(args.mint.toLowerCase())) {
    return { ok: false, status: 400, error: "fungible_mint_not_allowed" };
  }
  if (args.amount === undefined || args.amount === null) {
    return { ok: true, amount: 1 };
  }
  if (args.amount !== 1 && args.amount !== "1") {
    return { ok: false, status: 400, error: "nft_amount_must_be_1" };
  }
  return { ok: true, amount: 1 };
}
