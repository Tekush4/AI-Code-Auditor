/**
 * SECRET-002 — Expansão do secret scanner (Fase 8)
 * Novas categorias: GitHub token, Slack token, JWT, generic high-entropy string,
 * database connection string com credenciais embutidas.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { scanForSecrets } from "../../backend/src/modules/secrets/mask.ts";

test("SECRET-002: detecta GitHub personal access token", () => {
  const code = `const token = "ghp_1234567890abcdefghijklmnopqrstuvwx12";`;
  const findings = scanForSecrets(code, "config.js");
  assert.ok(findings.some(f => f.category === "github_token"));
});

test("SECRET-002: detecta Slack token", () => {
  const code = `const slack = "xoxb-123456789012-123456789012-abcdefghijklmnopqrstuvwx";`;
  const findings = scanForSecrets(code, "config.js");
  assert.ok(findings.some(f => f.category === "slack_token"));
});

test("SECRET-002: detecta JWT (estrutura header.payload.signature)", () => {
  const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.abc123signaturehere1234567890";
  const code = `const token = "${jwt}";`;
  const findings = scanForSecrets(code, "config.js");
  assert.ok(findings.some(f => f.category === "jwt"));
});

test("SECRET-002: detecta connection string de banco com credenciais embutidas", () => {
  const code = `const url = "postgres://admin:S3nhaForte123@db.internal.com:5432/prod";`;
  const findings = scanForSecrets(code, "config.js");
  assert.ok(findings.some(f => f.category === "database_connection_string"));
});

test("SECRET-002: connection string mascarada nunca expõe a senha", () => {
  const code = `const url = "postgres://admin:S3nhaForte123@db.internal.com:5432/prod";`;
  const findings = scanForSecrets(code, "config.js");
  const serialized = JSON.stringify(findings);
  assert.equal(serialized.includes("S3nhaForte123"), false);
});

test("SECRET-002: string de baixa entropia (nome de variável comum) não é falso positivo", () => {
  const code = `const message = "hello world this is not a secret at all";`;
  const findings = scanForSecrets(code, "app.js");
  assert.equal(findings.length, 0);
});
