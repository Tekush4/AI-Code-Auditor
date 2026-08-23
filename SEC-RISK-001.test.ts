import { test } from "node:test";
import assert from "node:assert/strict";
import { scoreFinding, scoreProject } from "../../backend/src/modules/risk/engine.ts";
import type { Finding } from "../../backend/src/modules/findings/model.ts";

function makeFinding(overrides: Partial<Finding>): Finding {
  return {
    id: "f1",
    title: "t",
    category: "Injection",
    severity: "HIGH",
    confidence: "high",
    cwe: "CWE-89",
    file: "a.ts",
    line: 1,
    remediation: "fix",
    status: "CONFIRMED",
    evidence: [{ source: "sast", ruleId: "R1", detail: "d" }],
    ...overrides,
  };
}

test("SEC-RISK-001: FALSE_POSITIVE nunca contribui para o score, mesmo sendo CRITICAL", () => {
  const finding = makeFinding({ severity: "CRITICAL", status: "FALSE_POSITIVE" });
  const result = scoreFinding(finding);
  assert.equal(result.score, 0);
});

test("SEC-RISK-001: severidade CRITICAL com confiança alta gera score maior que MEDIUM com confiança baixa", () => {
  const critical = scoreFinding(makeFinding({ severity: "CRITICAL", confidence: "high" }));
  const medium = scoreFinding(makeFinding({ severity: "MEDIUM", confidence: "low" }));
  assert.ok(critical.score > medium.score);
});

test("SEC-RISK-001: confiança mais baixa reduz o score da mesma severidade", () => {
  const high = scoreFinding(makeFinding({ severity: "HIGH", confidence: "high" }));
  const low = scoreFinding(makeFinding({ severity: "HIGH", confidence: "low" }));
  assert.ok(low.score < high.score);
});

test("SEC-RISK-001: score nunca ultrapassa 100", () => {
  const finding = makeFinding({
    severity: "CRITICAL",
    confidence: "high",
    evidence: [
      { source: "sast", ruleId: "R1", detail: "d" },
      { source: "secrets", ruleId: "R2", detail: "d" },
      { source: "dependencies", ruleId: "R3", detail: "d" },
    ],
  });
  const result = scoreFinding(finding);
  assert.ok(result.score <= 100);
});

test("SEC-RISK-001: scoreProject conta findings ativos por severidade e ignora FALSE_POSITIVE na contagem", () => {
  const findings = [
    makeFinding({ id: "1", severity: "CRITICAL", status: "CONFIRMED" }),
    makeFinding({ id: "2", severity: "CRITICAL", status: "FALSE_POSITIVE" }),
    makeFinding({ id: "3", severity: "LOW", status: "POTENTIAL" }),
  ];
  const summary = scoreProject(findings);
  assert.equal(summary.totalFindings, 2);
  assert.equal(summary.bySeverity.CRITICAL, 1);
  assert.equal(summary.bySeverity.LOW, 1);
});

test("SEC-RISK-001: overallScore do projeto reflete o pior finding (não a média)", () => {
  const findings = [
    makeFinding({ id: "1", severity: "LOW", confidence: "low" }),
    makeFinding({ id: "2", severity: "CRITICAL", confidence: "high" }),
  ];
  const summary = scoreProject(findings);
  const criticalScore = scoreFinding(findings[1]).score;
  assert.equal(summary.overallScore, criticalScore);
});
