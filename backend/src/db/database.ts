/**
 * Camada de banco de dados.
 *
 * MVP usa `node:sqlite` (built-in, sem dependência externa, já que este sandbox
 * não tem acesso a npm/rede). Em produção, trocar por PostgreSQL — a interface
 * `Database.query`/`Database.run` foi mantida deliberadamente simples para
 * facilitar a troca do driver sem reescrever os repositórios (ver ARCHITECTURE.md).
 */
import { DatabaseSync } from "node:sqlite";

export interface Database {
  run(sql: string, params?: unknown[]): void;
  all<T = Record<string, unknown>>(sql: string, params?: unknown[]): T[];
  get<T = Record<string, unknown>>(sql: string, params?: unknown[]): T | undefined;
}

export function openDatabase(path: string): Database {
  const raw = new DatabaseSync(path);

  raw.exec(`
    CREATE TABLE IF NOT EXISTS audits (
      id TEXT PRIMARY KEY,
      owner_id TEXT NOT NULL,
      repo_name TEXT NOT NULL,
      source_path TEXT,
      created_at TEXT NOT NULL
    );
  `);

  return {
    run(sql: string, params: unknown[] = []) {
      const stmt = raw.prepare(sql);
      stmt.run(...(params as never[]));
    },
    all<T>(sql: string, params: unknown[] = []): T[] {
      const stmt = raw.prepare(sql);
      return stmt.all(...(params as never[])) as T[];
    },
    get<T>(sql: string, params: unknown[] = []): T | undefined {
      const stmt = raw.prepare(sql);
      return stmt.get(...(params as never[])) as T | undefined;
    },
  };
}
