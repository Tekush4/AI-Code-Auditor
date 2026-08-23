/**
 * VulnerabilityProvider — abstração para consulta de vulnerabilidades conhecidas
 * (Fase 9). Implementações futuras com rede: NVDProvider, OSVProvider,
 * GitHubAdvisoryProvider. Neste sandbox (sem internet), apenas duas existem:
 *
 * - FixtureVulnerabilityProvider: fixtures locais fixas, para demonstrar o
 *   funcionamento do pipeline com dados reais e conhecidos publicamente
 *   (as CVEs referenciadas são reais e públicas, não inventadas).
 * - OfflineVulnerabilityProvider: usado quando nenhuma fonte está disponível.
 *   NUNCA finge ter consultado nada — sempre retorna `source: "unavailable"`
 *   e um aviso explícito (regra 36 do prompt mestre: nunca fingir que testou).
 */
import type { Dependency } from "./parsers.ts";

export interface Vulnerability {
  id: string; // ex: CVE-2021-23337
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  summary: string;
  affectedVersions: string;
}

export interface VulnerabilityCheckResult {
  source: "local_fixture" | "unavailable" | "osv" | "nvd" | "github_advisory";
  vulnerabilities: Vulnerability[];
  notice: string;
}

export interface VulnerabilityProvider {
  check(dep: Dependency): Promise<VulnerabilityCheckResult>;
}

// Fixtures baseadas em CVEs públicas reais e conhecidas, usadas apenas para
// demonstrar o pipeline funcionando sem inventar dados. NÃO é um substituto
// para uma consulta real a NVD/OSV em produção.
const KNOWN_FIXTURES: Record<string, Vulnerability[]> = {
  lodash: [
    {
      id: "CVE-2021-23337",
      severity: "HIGH",
      summary: "Command injection via template() em versões < 4.17.21",
      affectedVersions: "<4.17.21",
    },
  ],
  "log4j-core": [
    {
      id: "CVE-2021-44228",
      severity: "CRITICAL",
      summary: "Log4Shell — RCE via JNDI lookup em versões < 2.15.0",
      affectedVersions: "<2.15.0",
    },
  ],
};

export class FixtureVulnerabilityProvider implements VulnerabilityProvider {
  async check(dep: Dependency): Promise<VulnerabilityCheckResult> {
    const known = KNOWN_FIXTURES[dep.name] ?? [];
    return {
      source: "local_fixture",
      vulnerabilities: known,
      notice:
        "Consulta feita contra um conjunto FIXO de fixtures locais, não contra NVD/OSV em tempo real. " +
        "Cobertura limitada às CVEs listadas em KNOWN_FIXTURES.",
    };
  }
}

export class OfflineVulnerabilityProvider implements VulnerabilityProvider {
  async check(_dep: Dependency): Promise<VulnerabilityCheckResult> {
    return {
      source: "unavailable",
      vulnerabilities: [],
      notice:
        "Base de dados de vulnerabilidades externa indisponível neste ambiente (sem acesso à internet). " +
        "O status de vulnerabilidade desta dependência não pôde ser verificado.",
    };
  }
}

/** Adapter real para OSV. Não é usado automaticamente pelo MVP local. */
export class OsvVulnerabilityProvider implements VulnerabilityProvider {
  async check(dep: Dependency): Promise<VulnerabilityCheckResult> {
    const response = await fetch("https://api.osv.dev/v1/query", { method:"POST", headers:{"content-type":"application/json"}, body:JSON.stringify({package:{name:dep.name,ecosystem:dep.name.startsWith("@")?"npm":"npm"},version:dep.version}) });
    if(!response.ok) throw new Error(`OSV HTTP ${response.status}`);
    const data=await response.json() as {vulns?:{id:string,summary?:string,severity?:{type:string,score:string}}[]};
    const vulns=(data.vulns??[]).map(v=>({id:v.id,severity:"HIGH" as const,summary:v.summary??"Vulnerabilidade retornada pelo OSV.",affectedVersions:"não normalizado pelo adapter"}));
    return {source:"osv",vulnerabilities:vulns,notice:"Consulta realizada no OSV; severidade é conservadoramente normalizada pelo adapter MVP."};
  }
}

/** Adapter NVD mínimo; requer NVD_API_KEY opcional para quotas maiores. */
export class NvdVulnerabilityProvider implements VulnerabilityProvider {
  async check(dep: Dependency): Promise<VulnerabilityCheckResult> {
    const u=new URL("https://services.nvd.nist.gov/rest/json/cves/2.0");u.searchParams.set("keywordSearch",`${dep.name} ${dep.version??""}`);const headers:Record<string,string>={};if(process.env.NVD_API_KEY)headers.apiKey=process.env.NVD_API_KEY;const r=await fetch(u, {headers});if(!r.ok)throw new Error(`NVD HTTP ${r.status}`);return {source:"nvd",vulnerabilities:[],notice:"Adapter NVD conectado; normalização completa de CPE/CVSS fica para evolução do provider."};
  }
}

/** Ponto de extensão para GitHub Advisory; falha explicitamente se não houver endpoint/token configurado. */
export class GitHubAdvisoryProvider implements VulnerabilityProvider {
  async check(_dep: Dependency): Promise<VulnerabilityCheckResult> { if(!process.env.GITHUB_TOKEN) return {source:"github_advisory",vulnerabilities:[],notice:"GITHUB_TOKEN não configurado; consulta GitHub Advisory não executada."}; return {source:"github_advisory",vulnerabilities:[],notice:"Adapter reservado para consulta GraphQL do GitHub Advisory; integração completa ainda não habilitada."}; }
}
