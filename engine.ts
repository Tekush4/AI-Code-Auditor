/**
 * Risk Engine — Fase 14.
 *
 * Score determinístico e explicável (0-100), combinando:
 * - severidade base (impacto assumido do tipo de vulnerabilidade)
 * - confiança (reduz o score de achados menos certos)
 * - status (FALSE_POSITIVE nunca contribui para o risco do projeto)
 * - número de evidências independentes (mais fontes concordando = mais risco)
 *
 * Não existe fórmula "oficial" de risco em segurança — esta é uma heurística
 * documentada e auditável, não uma pretensão de precisão científica.
 */
import type { Finding, Severity } from "../findings/model.ts";

const BASE_SCORE: Record<Severity, number> = {
  CRITICAL: 90,
  HIGH: 70,
  MEDIUM: 45,
  LOW: 20,
  INFO: 5,
};

const CONFIDENCE_MULTIPLIER: Record<Finding["confidence"], number> = {
  high: 1.0,
  medium: 0.75,
  low: 0.5,
};

export interface RiskScore {
  findingId: string;
  score: number; // 0-100
  severity: Severity;
}

export function scoreFinding(finding: Finding): RiskScore {
  if (finding.status === "FALSE_POSITIVE") {
    return { findingId: finding.id, score: 0, severity: finding.severity };
  }

  const base = BASE_SCORE[finding.severity];
  const confidenceAdjusted = base * CONFIDENCE_MULTIPLIER[finding.confidence];
  const evidenceBonus = Math.min((finding.evidence.length - 1) * 5, 10); // até 2 fontes extras somam
  const score = Math.min(Math.round(confidenceAdjusted + evidenceBonus), 100);

  return { findingId: finding.id, score, severity: finding.severity };
}

export interface ProjectRiskSummary {
  overallScore: number; // maior score entre os findings ativos (pior caso primeiro)
  totalFindings: number;
  bySeverity: Record<Severity, number>;
  scores: RiskScore[];
}

export function scoreProject(findings: Finding[]): ProjectRiskSummary {
  const scores = findings.map(scoreFinding);
  const active = findings.filter(f => f.status !== "FALSE_POSITIVE");

  const bySeverity: Record<Severity, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  for (const f of active) bySeverity[f.severity]++;

  const overallScore = scores.reduce((max, s) => Math.max(max, s.score), 0);

  return { overallScore, totalFindings: active.length, bySeverity, scores };
}
