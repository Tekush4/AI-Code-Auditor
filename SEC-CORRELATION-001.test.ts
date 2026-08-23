import { test } from "node:test";
import assert from "node:assert/strict";
import { correlateFindings } from "../../backend/src/modules/correlation/engine.ts";
import type { Finding } from "../../backend/src/modules/findings/model.ts";

function makeFinding(overrides: Partial<Finding>): Finding {
  return {
    id: "base",
    title: "Base finding",
    category: "Injection",
    severity: "MEDIUM",
    confidence: "medium",
    cwe: "CWE-89",
    file: "src/db.ts",
    line: 10,
    remediation: "fix it",
    status: "LIKELY",
    evidence: [{ source: "sast", ruleId: "SAST-SQL-INJECTION", detail: "query(x)" }],
    ...overrides,
  };
}

test("SEC-CORRELATION-001: mesmo arquivo+linha+categoria de fontes diferentes vira 1 finding com 2 evidências", () => {
  const a = makeFinding({ id: "a", evidence: [{ source: "sast", ruleId: "SAST-SQL-INJECTION", detail: "x" }] });
  const b = makeFinding({
    id: "b",
    severity: "HIGH",
    confidence: "high",
    status: "CONFIRMED",
    evidence: [{ source: "dependencies", ruleId: "CVE-2024-0001", detail: "y" }],
  });

  const result = correlateFindings([a, b]);

  assert.equal(result.length, 1);
  assert.equal(result[0].evidence.length, 2);
});

test("SEC-CORRELATION-001: finding fundido assume a maior severidade/confiança/status observados", () => {
  const low = makeFinding({ id: "a", severity: "LOW", confidence: "low", status: "POTENTIAL" });
  const high = makeFinding({ id: "b", severity: "CRITICAL", confidence: "high", status: "CONFIRMED" });

  const [merged] = correlateFindings([low, high]);

  assert.equal(merged.severity, "CRITICAL");
  assert.equal(merged.confidence, "high");
  assert.equal(merged.status, "CONFIRMED");
});

test("SEC-CORRELATION-001: findings em arquivos diferentes NUNCA são fundidos", () => {
  const a = makeFinding({ id: "a", file: "src/a.ts" });
  const b = makeFinding({ id: "b", file: "src/b.ts" });

  const result = correlateFindings([a, b]);

  assert.equal(result.length, 2);
});

test("SEC-CORRELATION-001: findings de categorias diferentes no mesmo arquivo/linha NÃO são fundidos (evita falso agrupamento)", () => {
  const secret = makeFinding({ id: "a", category: "Hardcoded Secret" });
  const injection = makeFinding({ id: "b", category: "Injection" });

  const result = correlateFindings([secret, injection]);

  assert.equal(result.length, 2);
});

test("SEC-CORRELATION-001: findings sem linha definida (ex: secrets) ainda correlacionam por arquivo+categoria", () => {
  const a = makeFinding({ id: "a", line: null, category: "Hardcoded Secret" });
  const b = makeFinding({ id: "b", line: null, category: "Hardcoded Secret" });

  const result = correlateFindings([a, b]);

  assert.equal(result.length, 1);
});
