/**
 * Atomic daily USDC cap helpers.
 * Redis path uses INCRBYFLOAT + rollback; memory path mutates a shared counter.
 * NFT transfers must not call these — USDC only.
 */

export const DAILY_LIMIT_USD = 50000;
export const DAILY_USD_REDIS_KEY = "daily_transferred_usd";

export type ReserveResult =
  | { ok: true; used: number }
  | { ok: false; used: number; reason: "limit" | "backend" };

/** In-memory reserve: increment first, roll back if over limit. */
export function tryReserveMemory(
  state: { total: number },
  amountUsd: number,
  limit: number = DAILY_LIMIT_USD,
): ReserveResult {
  const next = state.total + amountUsd;
  if (next > limit) {
    return { ok: false, used: state.total, reason: "limit" };
  }
  state.total = next;
  return { ok: true, used: state.total };
}

/** Release a prior in-memory reservation (e.g. send failed after reserve). */
export function releaseMemory(state: { total: number }, amountUsd: number): void {
  state.total = Math.max(0, state.total - amountUsd);
}

export interface RedisDailyClient {
  incrbyfloat(key: string, amount: number): Promise<string | number>;
  ttl(key: string): Promise<number>;
  expire(key: string, seconds: number): Promise<number | boolean>;
}

/**
 * Redis reserve: INCRBYFLOAT first; if over limit, decrement and reject.
 * Caller must set TTL when needed via secondsUntilMidnight.
 */
export async function tryReserveRedis(
  redis: RedisDailyClient,
  amountUsd: number,
  secondsUntilMidnight: number,
  limit: number = DAILY_LIMIT_USD,
  key: string = DAILY_USD_REDIS_KEY,
): Promise<ReserveResult> {
  const newVal = parseFloat(String(await redis.incrbyfloat(key, amountUsd)));
  const ttl = await redis.ttl(key);
  if (ttl < 0) {
    await redis.expire(key, secondsUntilMidnight);
  }
  if (newVal > limit) {
    await redis.incrbyfloat(key, -amountUsd);
    const used = Math.max(0, newVal - amountUsd);
    return { ok: false, used, reason: "limit" };
  }
  return { ok: true, used: newVal };
}

export async function releaseRedis(
  redis: RedisDailyClient,
  amountUsd: number,
  key: string = DAILY_USD_REDIS_KEY,
): Promise<number> {
  const newVal = parseFloat(String(await redis.incrbyfloat(key, -amountUsd)));
  return newVal;
}
