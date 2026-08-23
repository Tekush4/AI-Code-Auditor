import { test } from "node:test";
import assert from "node:assert/strict";
import { buildJsonReport, buildMarkdownReport } from "../../backend/src/modules/reports/engine.ts";
import { scoreProject } from "../../backend/src/modules/risk/engine.ts";
import { fromSastFinding, fromSecretFinding, fromDependencyFinding } from "../../backend/src/modules/findings/model.ts";
import type { Finding } from "../../backend/src/modules/findings/model.ts";

function makeFinding(overrides: Partial<Finding>): Finding {
  return {
    id: "f1",
    title: "Possível SQL Injection",
    category: "Injection",
    severity: "CRITICAL",
    confidence: "high",
    cwe: "CWE-89",
    file: "src/db.ts",
    line: 42,
    remediation: "Use queries parametrizadas.",
    status: "CONFIRMED",
    evidence: [{ source: "sast", ruleId: "SAST-SQL-INJECTION", detail: "query(sql)" }],
    ...overrides,
  };
}

test("SEC-REPORT-001: relatório JSON nunca expõe o valor bruto de um secret, só o mascarado", () => {
  const secretFinding = fromSecretFinding({
    file: "config.ts",
    category: "aws_access_key",
    masked: "AKIA************1234",
    confidence: "high",
  });
  const risk = scoreProject([secretFinding]);
  const json = buildJsonReport({ projectName: "p", generatedAt: "2026-01-01T00:00:00Z", findings: [secretFinding], risk });

  assert.ok(json.includes("AKIA************1234"));
  assert.ok(!/AKIA[0-9A-Z]{16}/.test(json.replace("AKIA************1234", "")));
});

test("SEC-REPORT-001: JSON contém score geral, contagem por severidade e cada finding com seus campos essenciais", () => {
  const finding = makeFinding({});
  const risk = scoreProject([finding]);
  const json = buildJsonReport({ projectName: "meu-projeto", generatedAt: "2026-01-01T00:00:00Z", findings: [finding], risk });
  const parsed = JSON.parse(json);

  assert.equal(parsed.project, "meu-projeto");
  assert.equal(typeof parsed.summary.overallScore, "number");
  assert.equal(parsed.findings.length, 1);
  assert.equal(parsed.findings[0].id, "f1");
  assert.equal(parsed.findings[0].cwe, "CWE-89");
});

test("SEC-REPORT-001: relatório Markdown lida com projeto sem findings sem quebrar", () => {
  const risk = scoreProject([]);
  const md = buildMarkdownReport({ projectName: "vazio", generatedAt: "2026-01-01T00:00:00Z", findings: [], risk });
  assert.ok(md.includes("Nenhum finding ativo"));
});

test("SEC-REPORT-001: relatório Markdown lista severidade, arquivo:linha e remediação de cada finding", () => {
  const finding = makeFinding({});
  const risk = scoreProject([finding]);
  const md = buildMarkdownReport({ projectName: "p", generatedAt: "2026-01-01T00:00:00Z", findings: [finding], risk });

  assert.ok(md.includes("src/db.ts:42"));
  assert.ok(md.includes("Use queries parametrizadas."));
  assert.ok(md.includes("CRITICAL"));
});

test("SEC-REPORT-001 / model: finding de dependência sem vulnerabilidade conhecida não vira finding (dependência limpa não é achado)", () => {
  const clean = fromDependencyFinding(
    { packageName: "left-pad", version: "1.0.0", dev: false, source: "local_fixture", vulnerabilities: [], notice: "" },
    "package.json"
  );
  assert.equal(clean.length, 0);
});

test("SEC-REPORT-001 / model: finding de SAST com confiança 'high' vira status CONFIRMED; 'medium' vira LIKELY", () => {
  const highConf = fromSastFinding({
    ruleId: "SAST-DANGEROUS-EVAL", name: "eval", category: "Dangerous Functions", severity: "CRITICAL",
    cwe: "CWE-95", confidence: "high", file: "a.ts", line: 1, snippet: "eval(x)", remediation: "não use eval",
  });
  const mediumConf = fromSastFinding({
    ruleId: "SAST-COMMAND-INJECTION", name: "cmd", category: "Injection", severity: "HIGH",
    cwe: "CWE-78", confidence: "medium", file: "a.ts", line: 2, snippet: "exec(x)", remediation: "use execFile",
  });

  assert.equal(highConf.status, "CONFIRMED");
  assert.equal(mediumConf.status, "LIKELY");
});
