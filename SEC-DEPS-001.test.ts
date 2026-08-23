/**
 * SEC-DEPS-001 — Dependency Security (Fase 9)
 * Extrai dependências de manifestos e consulta um VulnerabilityProvider.
 * Como não há rede neste sandbox, usamos um provider local baseado em fixtures
 * e um OfflineProvider que informa honestamente que não pôde consultar a fonte real.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { parsePackageJson, parseRequirementsTxt } from "../../backend/src/modules/dependencies/parsers.ts";
import { FixtureVulnerabilityProvider, OfflineVulnerabilityProvider } from "../../backend/src/modules/dependencies/providers.ts";
import { analyzeDependencies } from "../../backend/src/modules/dependencies/analyzer.ts";

test("SEC-DEPS-001: extrai dependências de package.json", () => {
  const pkg = JSON.stringify({
    dependencies: { lodash: "4.17.15", express: "^4.18.0" },
    devDependencies: { jest: "29.0.0" },
  });
  const deps = parsePackageJson(pkg);
  assert.equal(deps.length, 3);
  assert.ok(deps.some(d => d.name === "lodash" && d.version === "4.17.15"));
  assert.ok(deps.some(d => d.name === "jest" && d.dev === true));
});

test("SEC-DEPS-001: extrai dependências de requirements.txt (com e sem versão pinada)", () => {
  const content = "flask==2.0.1\nrequests>=2.25.0\nnumpy\n";
  const deps = parseRequirementsTxt(content);
  assert.equal(deps.length, 3);
  assert.ok(deps.some(d => d.name === "flask" && d.version === "2.0.1"));
  assert.ok(deps.some(d => d.name === "numpy" && d.version === null));
});

test("SEC-DEPS-001: FixtureVulnerabilityProvider encontra CVE conhecida em fixture local", async () => {
  const provider = new FixtureVulnerabilityProvider();
  const result = await provider.check({ name: "lodash", version: "4.17.15", dev: false });
  assert.equal(result.source, "local_fixture");
  assert.ok(result.vulnerabilities.length > 0);
  assert.ok(result.vulnerabilities[0].id.startsWith("CVE-"));
});

test("SEC-DEPS-001: OfflineVulnerabilityProvider nunca finge ter consultado uma fonte real", async () => {
  const provider = new OfflineVulnerabilityProvider();
  const result = await provider.check({ name: "qualquer-pacote", version: "1.0.0", dev: false });
  assert.equal(result.source, "unavailable");
  assert.equal(result.vulnerabilities.length, 0);
  assert.ok(result.notice.includes("indisponível") || result.notice.includes("não pôde"));
});

test("SEC-DEPS-001: analyzeDependencies combina parsing + provider e nunca declara 100% de cobertura", async () => {
  const pkg = JSON.stringify({ dependencies: { lodash: "4.17.15", express: "4.18.0" } });
  const report = await analyzeDependencies(pkg, "package.json", new FixtureVulnerabilityProvider());
  assert.equal(report.totalDependencies, 2);
  assert.ok(report.limitations.length > 0, "deve declarar limitações explicitamente");
  assert.ok(report.findings.some(f => f.packageName === "lodash"));
});
