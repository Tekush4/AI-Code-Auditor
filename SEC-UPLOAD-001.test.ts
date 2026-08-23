/**
 * SEC-UPLOAD-001 — Import Engine (Fase 6)
 * Cobre: proteção contra path traversal/zip-slip ao importar um projeto local,
 * limites de tamanho/quantidade de arquivos, e detecção de linguagem.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, mkdirSync, symlinkSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { importLocalDirectory, PathTraversalError } from "../../backend/src/modules/import/localImporter.ts";
import { detectLanguages } from "../../backend/src/modules/import/languageDetector.ts";

function makeTempProject(files: Record<string, string>): string {
  const dir = mkdtempSync(path.join(tmpdir(), "aica-import-"));
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(dir, rel);
    mkdirSync(path.dirname(full), { recursive: true });
    writeFileSync(full, content);
  }
  return dir;
}

test("SEC-UPLOAD-001: importa arquivos normais de um projeto", () => {
  const dir = makeTempProject({
    "package.json": '{"name":"demo"}',
    "src/index.js": "console.log('hi')",
  });
  const result = importLocalDirectory(dir);
  assert.equal(result.files.some(f => f.relativePath === "package.json"), true);
  assert.equal(result.files.some(f => f.relativePath === "src/index.js"), true);
  rmSync(dir, { recursive: true, force: true });
});

test("SEC-UPLOAD-001: symlink apontando para fora do diretório base é rejeitado (zip-slip)", () => {
  const dir = makeTempProject({ "package.json": "{}" });
  const outsideSecretFile = path.join(tmpdir(), `secret-${Date.now()}.txt`);
  writeFileSync(outsideSecretFile, "conteudo sensivel fora do projeto");
  const evilLink = path.join(dir, "escape-link");
  symlinkSync(outsideSecretFile, evilLink);

  const result = importLocalDirectory(dir);
  // o link nunca deve ser seguido nem seu conteúdo incluído no resultado
  assert.equal(result.files.some(f => f.relativePath === "escape-link"), false);
  assert.ok(result.rejected.some(r => r.reason === "symlink_outside_base"));

  rmSync(dir, { recursive: true, force: true });
  rmSync(outsideSecretFile, { force: true });
});

test("SEC-UPLOAD-001: limite de quantidade de arquivos é respeitado", () => {
  const files: Record<string, string> = {};
  for (let i = 0; i < 20; i++) files[`file-${i}.txt`] = "x";
  const dir = makeTempProject(files);

  const result = importLocalDirectory(dir, { maxFiles: 5, maxTotalBytes: 10_000_000 });
  assert.equal(result.files.length <= 5, true);
  assert.equal(result.truncated, true);

  rmSync(dir, { recursive: true, force: true });
});

test("SEC-UPLOAD-001: detecta JavaScript/Node por package.json", () => {
  const langs = detectLanguages(["package.json", "src/index.js"]);
  assert.ok(langs.some(l => l.language === "javascript"));
});

test("SEC-UPLOAD-001: detecta Python por requirements.txt", () => {
  const langs = detectLanguages(["requirements.txt", "app/main.py"]);
  assert.ok(langs.some(l => l.language === "python"));
});

test("SEC-UPLOAD-001: detecta múltiplas linguagens em projeto poliglota", () => {
  const langs = detectLanguages(["package.json", "go.mod", "Cargo.toml"]);
  const names = langs.map(l => l.language);
  assert.ok(names.includes("javascript"));
  assert.ok(names.includes("go"));
  assert.ok(names.includes("rust"));
});

test("SEC-UPLOAD-001: projeto sem manifests conhecidos retorna lista vazia (sem falso positivo)", () => {
  const langs = detectLanguages(["README.md", "LICENSE"]);
  assert.equal(langs.length, 0);
});
