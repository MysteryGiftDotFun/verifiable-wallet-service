/**
 * Policy for POST /transfer-nft: amount must be 1; known fungible mints blocked.
 * Callers pass blockedMints (USDC/USDG) so tests can inject fixtures.
 */

export type NftTransferDecision =
  | { ok: true; amount: 1 }
  | { ok: false; status: 400; error: string };

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
