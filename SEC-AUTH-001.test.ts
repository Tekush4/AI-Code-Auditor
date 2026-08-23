/**
 * SEC-AUTH-001 — Password hashing
 *
 * TESTE: Senhas nunca devem ser armazenadas ou comparadas em texto puro.
 * TECNOLOGIA: Node.js (node:crypto, scrypt)
 * SEVERIDADE: CRITICAL
 *
 * Fase TDD: este teste foi escrito ANTES da implementação existir (RED).
 * Rode com: npx tsx --test security-tests/authentication/SEC-AUTH-001.test.ts
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { hashPassword, verifyPassword } from "../../backend/src/modules/auth/password.ts";

test("SEC-AUTH-001: hash nunca é igual à senha original", async () => {
  const hash = await hashPassword("Sup3rSecret!");
  assert.notEqual(hash, "Sup3rSecret!");
});

test("SEC-AUTH-001: hash da mesma senha duas vezes produz valores diferentes (salt aleatório)", async () => {
  const h1 = await hashPassword("Sup3rSecret!");
  const h2 = await hashPassword("Sup3rSecret!");
  assert.notEqual(h1, h2, "hashes idênticos indicam ausência de salt aleatório");
});

test("SEC-AUTH-001: verifyPassword aceita a senha correta", async () => {
  const hash = await hashPassword("Sup3rSecret!");
  assert.equal(await verifyPassword("Sup3rSecret!", hash), true);
});

test("SEC-AUTH-001: verifyPassword rejeita senha incorreta", async () => {
  const hash = await hashPassword("Sup3rSecret!");
  assert.equal(await verifyPassword("senha-errada", hash), false);
});

test("SEC-AUTH-001: hash não contém a senha original como substring (proteção básica de log)", async () => {
  const hash = await hashPassword("Sup3rSecret!");
  assert.equal(hash.includes("Sup3rSecret!"), false);
});
