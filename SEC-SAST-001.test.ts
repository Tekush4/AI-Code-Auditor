/**
 * SEC-SAST-001 — SAST Engine baseado em AST (Fase 7)
 * Usa o TypeScript Compiler API (já instalado globalmente, sem dependência de rede)
 * para parsear JS/TS em uma AST real — não regex — e detectar padrões perigosos.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { analyzeSource } from "../../backend/src/modules/sast/engine.ts";

test("SEC-SAST-001: detecta uso de eval() (CWE-95)", () => {
  const code = `function run(userInput) { return eval(userInput); }`;
  const findings = analyzeSource(code, "app.js");
  const f = findings.find(f => f.ruleId === "SAST-DANGEROUS-EVAL");
  assert.ok(f, "deveria detectar eval()");
  assert.equal(f?.cwe, "CWE-95");
  assert.equal(f?.severity, "CRITICAL");
  assert.equal(f?.line, 1);
});

test("SEC-SAST-001: detecta command injection via child_process.exec com input dinâmico (CWE-78)", () => {
  const code = `
const { exec } = require("child_process");
function run(userInput) {
  exec("ls " + userInput, () => {});
}`;
  const findings = analyzeSource(code, "app.js");
  const f = findings.find(f => f.ruleId === "SAST-COMMAND-INJECTION");
  assert.ok(f, "deveria detectar exec() com concatenação de string");
  assert.equal(f?.cwe, "CWE-78");
});

test("SEC-SAST-001: NÃO reporta falso positivo em exec() com string literal fixa", () => {
  const code = `
const { exec } = require("child_process");
exec("ls -la /var/log", () => {});`;
  const findings = analyzeSource(code, "app.js");
  const f = findings.find(f => f.ruleId === "SAST-COMMAND-INJECTION");
  assert.equal(f, undefined, "string literal fixa não deveria disparar o alerta");
});

test("SEC-SAST-001: detecta hash fraco MD5/SHA1 (CWE-327)", () => {
  const code = `
const crypto = require("crypto");
function hash(pw) { return crypto.createHash("md5").update(pw).digest("hex"); }`;
  const findings = analyzeSource(code, "auth.js");
  const f = findings.find(f => f.ruleId === "SAST-WEAK-HASH");
  assert.ok(f, "deveria detectar uso de md5");
  assert.equal(f?.cwe, "CWE-327");
});

test("SEC-SAST-001: detecta possível SQL injection por concatenação de string em query (CWE-89)", () => {
  const code = `
function getUser(db, id) {
  return db.query("SELECT * FROM users WHERE id = " + id);
}`;
  const findings = analyzeSource(code, "db.js");
  const f = findings.find(f => f.ruleId === "SAST-SQL-INJECTION");
  assert.ok(f, "deveria detectar concatenação em query SQL");
  assert.equal(f?.cwe, "CWE-89");
});

test("SEC-SAST-001: NÃO reporta falso positivo em query parametrizada", () => {
  const code = `
function getUser(db, id) {
  return db.query("SELECT * FROM users WHERE id = ?", [id]);
}`;
  const findings = analyzeSource(code, "db.js");
  const f = findings.find(f => f.ruleId === "SAST-SQL-INJECTION");
  assert.equal(f, undefined, "query parametrizada não deveria disparar o alerta");
});

test("SEC-SAST-001: cada finding possui todos os campos exigidos pelo prompt mestre", () => {
  const code = `eval("2+2")`;
  const findings = analyzeSource(code, "app.js");
  const f = findings[0];
  for (const field of ["ruleId", "name", "category", "severity", "cwe", "confidence", "file", "line", "remediation"]) {
    assert.ok(field in (f as object), `campo ausente: ${field}`);
  }
});
