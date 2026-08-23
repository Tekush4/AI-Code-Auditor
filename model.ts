/**
 * Finding model — Fase 13 (Correlation Engine), pré-requisito.
 *
 * Os três engines existentes (SAST, Secrets, Dependencies) produzem formatos
 * próprios (`SastFinding`, `SecretFinding`, `DependencyFinding`). Para
 * correlacionar, pontuar risco (Fase 14) e gerar relatórios (Fase 15)
 * precisamos de um formato único. Este módulo APENAS normaliza — não
 * reimplementa nenhuma das análises existentes (regra 5 do prompt mestre:
 * não reescrever o que já funciona).
 */
import type { SastFinding } from "../sast/engine.ts";
import type { SecretFinding } from "../secrets/mask.ts";
import type { DependencyFinding } from "../dependencies/analyzer.ts";

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
export type Confidence = "high" | "medium" | "low";
export type FindingStatus = "CONFIRMED" | "LIKELY" | "POTENTIAL" | "FALSE_POSITIVE";
export type EngineSource = "sast" | "secrets" | "dependencies" | "architecture" | "performance" | "ai";

export interface Evidence {
  source: EngineSource;
  ruleId: string;
  detail: string;
}

export interface Finding {
  /** Determinístico: mesmo achado normalizado sempre gera o mesmo id. */
  id: string;
  title: string;
  category: string;
  severity: Severity;
  confidence: Confidence;
  cwe: string | null;
  file: string;
  line: number | null;
  remediation: string;
  status: FindingStatus;
  evidence: Evidence[];
}

function makeId(parts: (string | number | null)[]): string {
  return parts.map(p => String(p ?? "?")).join(":");
}

/** Mapeia confidence do SAST engine para o status inicial do finding (regra 21). */
function statusFromConfidence(confidence: Confidence): FindingStatus {
  if (confidence === "high") return "CONFIRMED";
  if (confidence === "medium") return "LIKELY";
  return "POTENTIAL";
}

export function fromSastFinding(f: SastFinding): Finding {
  return {
    id: makeId(["sast", f.ruleId, f.file, f.line]),
    title: f.name,
    category: f.category,
    severity: f.severity,
    confidence: f.confidence,
    cwe: f.cwe,
    file: f.file,
    line: f.line,
    remediation: f.remediation,
    status: statusFromConfidence(f.confidence),
    evidence: [{ source: "sast", ruleId: f.ruleId, detail: f.snippet }],
  };
}

/**
 * Secrets nunca são CONFIRMED automaticamente sem revisão humana — um secret
 * mascarado detectado por regex pode ser um valor de teste/fixture (regra 21:
 * nunca promover suspeita a confirmado sem evidência suficiente).
 */
export function fromSecretFinding(f: SecretFinding): Finding {
  return {
    id: makeId(["secrets", f.category, f.file, f.masked]),
    title: `Possível segredo exposto (${f.category})`,
    category: "Hardcoded Secret",
    severity: "CRITICAL",
    confidence: f.confidence,
    cwe: "CWE-798",
    file: f.file,
    line: null,
    remediation: "Revogue a credencial, mova para um secret manager e remova do histórico do Git.",
    status: f.confidence === "high" ? "LIKELY" : "POTENTIAL",
    evidence: [{ source: "secrets", ruleId: f.category, detail: f.masked }],
  };
}

function severityFromVulnSet(vulns: { severity: string }[]): Severity {
  const order: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
  for (const level of order) {
    if (vulns.some(v => v.severity === level)) return level;
  }
  return "INFO";
}

/** Só gera Finding para dependências com vulnerabilidade conhecida — dependência limpa não é achado. */
export function fromDependencyFinding(f: DependencyFinding, projectFile: string): Finding[] {
  const vulns = f.vulnerabilities as { id: string; severity: Severity; summary: string }[];
  if (vulns.length === 0) return [];

  return vulns.map(v => ({
    id: makeId(["dependencies", f.packageName, f.version, v.id]),
    title: `Dependência vulnerável: ${f.packageName}@${f.version ?? "?"} (${v.id})`,
    category: "Vulnerable Dependency",
    severity: v.severity,
    confidence: f.source === "local_fixture" ? "high" : "low",
    cwe: null,
    file: projectFile,
    line: null,
    remediation: `Atualize ${f.packageName} para uma versão não afetada por ${v.id}.`,
    status: f.source === "local_fixture" ? "CONFIRMED" : "POTENTIAL",
    evidence: [{ source: "dependencies", ruleId: v.id, detail: v.summary }],
  }));
}
