/**
 * Parsers de manifesto (Fase 9). Cada parser extrai {name, version, dev} sem
 * assumir nada além do que está literalmente escrito no arquivo.
 */
export interface Dependency {
  name: string;
  version: string | null;
  dev: boolean;
}

export function parsePackageJson(content: string): Dependency[] {
  const parsed = JSON.parse(content) as {
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
  };
  const deps: Dependency[] = [];

  for (const [name, version] of Object.entries(parsed.dependencies ?? {})) {
    deps.push({ name, version: version.replace(/^[\^~>=<]+/, ""), dev: false });
  }
  for (const [name, version] of Object.entries(parsed.devDependencies ?? {})) {
    deps.push({ name, version: version.replace(/^[\^~>=<]+/, ""), dev: true });
  }
  return deps;
}

export function parseRequirementsTxt(content: string): Dependency[] {
  const deps: Dependency[] = [];
  const lines = content.split("\n").map(l => l.trim()).filter(l => l && !l.startsWith("#"));

  for (const line of lines) {
    const match = line.match(/^([A-Za-z0-9_.-]+)\s*(==|>=|<=|~=)?\s*([A-Za-z0-9.]+)?/);
    if (!match) continue;
    const [, name, , version] = match;
    deps.push({ name, version: version ?? null, dev: false });
  }
  return deps;
}
