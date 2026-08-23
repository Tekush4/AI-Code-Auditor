import { parsePackageJson } from "./parsers.ts";
import type { VulnerabilityProvider } from "./providers.ts";

export interface DependencyFinding {
  packageName: string;
  version: string | null;
  dev: boolean;
  source: string;
  vulnerabilities: unknown[];
  notice: string;
}

export interface DependencyReport {
  totalDependencies: number;
  findings: DependencyFinding[];
  limitations: string[];
}

/**
 * Analisa um manifesto package.json (Fase 9). Suporte a outros manifestos
 * (requirements.txt, go.mod, Cargo.toml, pom.xml) segue a mesma forma —
 * ver parsers.ts para os já implementados.
 */
export async function analyzeDependencies(
  manifestContent: string,
  manifestFileName: string,
  provider: VulnerabilityProvider
): Promise<DependencyReport> {
  const deps = manifestFileName.endsWith("package.json")
    ? parsePackageJson(manifestContent)
    : [];

  const findings: DependencyFinding[] = [];
  for (const dep of deps) {
    const result = await provider.check(dep);
    findings.push({
      packageName: dep.name,
      version: dep.version,
      dev: dep.dev,
      source: result.source,
      vulnerabilities: result.vulnerabilities,
      notice: result.notice,
    });
  }

  return {
    totalDependencies: deps.length,
    findings,
    limitations: [
      "Este relatório não representa uma verificação completa de todas as vulnerabilidades existentes.",
      `Fonte de dados usada: ${findings[0]?.source ?? "nenhuma dependência encontrada"}.`,
      "Dependências transitivas (sub-dependências) não são analisadas nesta versão.",
    ],
  };
}
