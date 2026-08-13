import { strict as assert } from "node:assert";
import { test } from "node:test";
import {
  DAILY_LIMIT_USD,
  releaseMemory,
  tryReserveMemory,
  tryReserveRedis,
  releaseRedis,
  type RedisDailyClient,
} from "./daily-cap";

test("tryReserveMemory under limit succeeds", () => {
  const state = { total: 100 };
  const result = tryReserveMemory(state, 50);
  assert.equal(result.ok, true);
  if (result.ok) assert.equal(result.used, 150);
  assert.equal(state.total, 150);
});

test("tryReserveMemory that would exceed fails and does not keep increment", () => {
  const state = { total: DAILY_LIMIT_USD - 10 };
  const result = tryReserveMemory(state, 20);
  assert.equal(result.ok, false);
  if (!result.ok) {
    assert.equal(result.reason, "limit");
    assert.equal(result.used, DAILY_LIMIT_USD - 10);
  }
  assert.equal(state.total, DAILY_LIMIT_USD - 10);
});

test("releaseMemory restores room", () => {
  const state = { total: 500 };
  releaseMemory(state, 200);
  assert.equal(state.total, 300);
  const again = tryReserveMemory(state, 200);
  assert.equal(again.ok, true);
  assert.equal(state.total, 500);
});

test("tryReserveRedis under limit succeeds and sets TTL when missing", async () => {
  let value = 0;
  let expireSecs: number | null = null;
  const redis: RedisDailyClient = {
    async incrbyfloat(_key, amount) {
      value += amount;
      return String(value);
    },
    async ttl() {
      return expireSecs === null ? -1 : 3600;
    },
    async expire(_key, seconds) {
      expireSecs = seconds;
      return 1;
    },
  };
  const result = await tryReserveRedis(redis, 100, 86400);
  assert.equal(result.ok, true);
  if (result.ok) assert.equal(result.used, 100);
  assert.equal(value, 100);
  assert.equal(expireSecs, 86400);
});

test("tryReserveRedis over limit decrements back", async () => {
  let value = DAILY_LIMIT_USD - 5;
  const redis: RedisDailyClient = {
    async incrbyfloat(_key, amount) {
      value += amount;
      return String(value);
    },
    async ttl() {
      return 1000;
    },
    async expire() {
      return 1;
    },
  };
  const result = await tryReserveRedis(redis, 20, 86400);
  assert.equal(result.ok, false);
  if (!result.ok) {
    assert.equal(result.reason, "limit");
    assert.equal(result.used, DAILY_LIMIT_USD - 5);
  }
  assert.equal(value, DAILY_LIMIT_USD - 5);
});

test("releaseRedis restores room", async () => {
  let value = 1000;
  const redis: RedisDailyClient = {
    async incrbyfloat(_key, amount) {
      value += amount;
      return String(value);
    },
    async ttl() {
      return 1000;
    },
    async expire() {
      return 1;
    },
  };
  const after = await releaseRedis(redis, 400);
  assert.equal(after, 600);
  assert.equal(value, 600);
});
