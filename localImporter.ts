/**
 * Import Engine — importação a partir de diretório local (Fase 6).
 *
 * Proteção contra "zip-slip" / path traversal (seção 5 e 18 do prompt: "upload
 * inseguro", "path traversal"): mesmo importando de um diretório local (não um
 * .zip ainda), qualquer symlink que aponte para FORA do diretório base é
 * detectado e rejeitado — nunca seguido, nunca incluído no resultado.
 *
 * Limitação declarada: importação direta de arquivo .zip não está implementada
 * neste sandbox (exigiria uma biblioteca de descompactação via npm, indisponível
 * sem rede). A interface abaixo (ImportResult) é a mesma que será usada quando o
 * ZipImporter for adicionado, então o restante do pipeline (language detector,
 * SAST, etc.) não precisa mudar.
 */
import { readdirSync, statSync, lstatSync, readFileSync, realpathSync } from "node:fs";
import path from "node:path";

export class PathTraversalError extends Error {
  constructor(relativePath: string) {
    super(`Caminho fora do diretório base rejeitado: ${relativePath}`);
    this.name = "PathTraversalError";
  }
}

export interface ImportedFile {
  relativePath: string;
  sizeBytes: number;
}

export interface RejectedEntry {
  relativePath: string;
  reason: "symlink_outside_base" | "max_files_exceeded" | "max_total_bytes_exceeded";
}

export interface ImportResult {
  files: ImportedFile[];
  rejected: RejectedEntry[];
  truncated: boolean;
  totalBytes: number;
}

export interface ImportOptions {
  maxFiles?: number;
  maxTotalBytes?: number;
  ignoreDirs?: string[];
}

const DEFAULT_IGNORE = new Set(["node_modules", ".git", "dist", "build", "__pycache__", ".venv"]);

export function importLocalDirectory(baseDir: string, options: ImportOptions = {}): ImportResult {
  const maxFiles = options.maxFiles ?? 20_000;
  const maxTotalBytes = options.maxTotalBytes ?? 200 * 1024 * 1024; // 200MB
  const ignoreDirs = new Set([...DEFAULT_IGNORE, ...(options.ignoreDirs ?? [])]);

  const realBase = realpathSync(baseDir);
  const files: ImportedFile[] = [];
  const rejected: RejectedEntry[] = [];
  let totalBytes = 0;
  let truncated = false;

  function walk(dir: string) {
    if (truncated) return;
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return; // diretório ilegível — não derruba o import inteiro
    }

    for (const entry of entries) {
      if (truncated) return;

      const fullPath = path.join(dir, entry.name);
      const relativePath = path.relative(realBase, fullPath);

      if (entry.isSymbolicLink()) {
        // Resolve o alvo real do symlink e confirma que continua DENTRO do baseDir.
        let target: string;
        try {
          target = realpathSync(fullPath);
        } catch {
          rejected.push({ relativePath, reason: "symlink_outside_base" });
          continue;
        }
        const relToBase = path.relative(realBase, target);
        const escapesBase = relToBase.startsWith("..") || path.isAbsolute(relToBase);
        if (escapesBase) {
          rejected.push({ relativePath, reason: "symlink_outside_base" });
          continue;
        }
        // symlink aponta para dentro do próprio projeto — segue normalmente
      }

      const stat = statSync(fullPath);

      if (stat.isDirectory()) {
        if (ignoreDirs.has(entry.name)) continue;
        walk(fullPath);
        continue;
      }

      if (files.length >= maxFiles) {
        truncated = true;
        rejected.push({ relativePath, reason: "max_files_exceeded" });
        return;
      }

      if (totalBytes + stat.size > maxTotalBytes) {
        truncated = true;
        rejected.push({ relativePath, reason: "max_total_bytes_exceeded" });
        return;
      }

      files.push({ relativePath, sizeBytes: stat.size });
      totalBytes += stat.size;
    }
  }

  walk(realBase);

  return { files, rejected, truncated, totalBytes };
}

/** Lê o conteúdo de um arquivo já validado pelo import (path já é conhecido/seguro). */
export function readImportedFile(baseDir: string, relativePath: string): string {
  const realBase = realpathSync(baseDir);
  const fullPath = path.join(realBase, relativePath);
  const resolved = realpathSync(fullPath);
  const rel = path.relative(realBase, resolved);
  if (rel.startsWith("..") || path.isAbsolute(rel)) {
    throw new PathTraversalError(relativePath);
  }
  return readFileSync(resolved, "utf8");
}
