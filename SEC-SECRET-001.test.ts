/**
 * SEC-SECRET-001 — Detecção e mascaramento de secrets
 * SEVERIDADE: CRITICAL
 * Regra: nunca mostrar secret completo em relatório, log ou frontend (seção 7 do prompt).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { maskSecret, scanForSecrets } from "../../backend/src/modules/secrets/mask.ts";

test("SEC-SECRET-001: mascara mantendo apenas prefixo e 4 últimos chars", () => {
  const input = "sk_live_ABCDEFGH1234"; // remainder = "ABCDEFGH1234" (12 chars: 8 mascarados + 4 finais)
  const masked = maskSecret(input);
  assert.equal(masked, "sk_live_********1234");
});

test("SEC-SECRET-001: masked nunca contém o segredo original completo", () => {
  const input = "sk_live_ABCDEFGHIJKLMNOP1234";
  const masked = maskSecret(input);
  assert.equal(masked.includes("ABCDEFGHIJKLMNOP"), false);
});

test("SEC-SECRET-001: scanForSecrets detecta AWS access key em código", () => {
  const code = `const key = "AKIAIOSFODNN7EXAMPLE";`;
  const findings = scanForSecrets(code, "config.js");
  assert.equal(findings.length >= 1, true);
  assert.equal(findings[0].category, "aws_access_key");
});

test("SEC-SECRET-001: scanForSecrets nunca retorna o valor bruto do secret, só a versão mascarada", () => {
  const code = `const key = "AKIAIOSFODNN7EXAMPLE";`;
  const findings = scanForSecrets(code, "config.js");
  const serialized = JSON.stringify(findings);
  assert.equal(serialized.includes("AKIAIOSFODNN7EXAMPLE"), false);
});

test("SEC-SECRET-001: scanForSecrets detecta private key PEM", () => {
  const code = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n-----END RSA PRIVATE KEY-----";
  const findings = scanForSecrets(code, "id_rsa");
  assert.equal(findings.some(f => f.category === "private_key"), true);
});

test("SEC-SECRET-001: código sem secrets não gera falso positivo", () => {
  const code = `function add(a, b) { return a + b; }`;
  const findings = scanForSecrets(code, "math.js");
  assert.equal(findings.length, 0);
});
