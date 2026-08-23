/**
 * Detecção de linguagem/ecossistema por arquivos de manifesto (Fase 6).
 * Arquitetura extensível: cada entrada em MANIFEST_MAP pode futuramente
 * disparar um analyzer específico em backend/src/modules/analyzers/<linguagem>/.
 */
export interface DetectedLanguage {
  language: string;
  manifestFile: string;
  ecosystem: string;
}

const MANIFEST_MAP: Record<string, { language: string; ecosystem: string }> = {
  "package.json": { language: "javascript", ecosystem: "npm" },
  "tsconfig.json": { language: "typescript", ecosystem: "npm" },
  "requirements.txt": { language: "python", ecosystem: "pip" },
  "pyproject.toml": { language: "python", ecosystem: "poetry/pip" },
  "go.mod": { language: "go", ecosystem: "go modules" },
  "Cargo.toml": { language: "rust", ecosystem: "cargo" },
  "pom.xml": { language: "java", ecosystem: "maven" },
  "build.gradle": { language: "java", ecosystem: "gradle" },
  "composer.json": { language: "php", ecosystem: "composer" },
  Gemfile: { language: "ruby", ecosystem: "bundler" },
};

/**
 * Recebe uma lista de caminhos relativos (de `importLocalDirectory`) e detecta
 * quais linguagens/ecossistemas estão presentes, com base em manifestos conhecidos.
 * Não afirma "100% das tecnologias existentes" — apenas os manifestos mapeados
 * (seção 3 do prompt: nunca alegar cobertura total).
 */
export function detectLanguages(relativePaths: string[]): DetectedLanguage[] {
  const found = new Map<string, DetectedLanguage>();

  for (const relPath of relativePaths) {
    const fileName = relPath.split("/").pop() ?? relPath;
    const mapping = MANIFEST_MAP[fileName];
    if (mapping && !found.has(mapping.language)) {
      found.set(mapping.language, { language: mapping.language, manifestFile: fileName, ecosystem: mapping.ecosystem });
    }
  }

  return [...found.values()];
}
