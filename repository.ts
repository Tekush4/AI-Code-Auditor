/**
 * AuditRepository — toda operação exige o ID do usuário que está pedindo,
 * e verifica ownership ANTES de retornar ou modificar qualquer dado.
 *
 * Isso implementa a regra 17 do prompt mestre: "Não confie apenas no frontend.
 * Toda operação sensível deve ser autorizada no backend." e a regra 28
 * (multi-tenancy: Usuário A nunca vê dado do Usuário B).
 *
 * Todas as queries usam parâmetros (?) — nunca concatenação de string (regra 14).
 */
import { randomUUID } from "node:crypto";
import type { Database } from "./database.ts";

export class AuthorizationError extends Error {
  constructor(message = "Acesso negado a este recurso.") {
    super(message);
    this.name = "AuthorizationError";
  }
}

export interface Audit {
  id: string;
  ownerId: string;
  repoName: string;
  createdAt: string;
  sourcePath: string | null;
}

interface AuditRow {
  id: string;
  owner_id: string;
  repo_name: string;
  created_at: string;
  source_path: string | null;
}

function rowToAudit(row: AuditRow): Audit {
  return { id: row.id, ownerId: row.owner_id, repoName: row.repo_name, createdAt: row.created_at, sourcePath: row.source_path ?? null };
}

export class AuditRepository {
  constructor(private db: Database) {}

  createAudit(input: { ownerId: string; repoName: string; sourcePath?: string | null }): string {
    const id = randomUUID();
    this.db.run(
      "INSERT INTO audits (id, owner_id, repo_name, source_path, created_at) VALUES (?, ?, ?, ?, ?)",
      [id, input.ownerId, input.repoName, input.sourcePath ?? null, new Date().toISOString()]
    );
    return id;
  }

  /**
   * Busca uma auditoria SOMENTE se pertencer ao userId informado.
   * Nunca retorna dado de outro dono — lança AuthorizationError em vez de
   * vazar "not found" vs "forbidden" (evita enumeração de IDs válidos).
   */
  getAuditForUser(auditId: string, userId: string): Audit {
    const row = this.db.get<AuditRow>("SELECT * FROM audits WHERE id = ?", [auditId]);
    if (!row || row.owner_id !== userId) {
      throw new AuthorizationError();
    }
    return rowToAudit(row);
  }

  deleteAuditForUser(auditId: string, userId: string): void {
    const row = this.db.get<AuditRow>("SELECT * FROM audits WHERE id = ?", [auditId]);
    if (!row || row.owner_id !== userId) {
      throw new AuthorizationError();
    }
    this.db.run("DELETE FROM audits WHERE id = ?", [auditId]);
  }

  listAuditsForUser(userId: string): Audit[] {
    const rows = this.db.all<AuditRow>("SELECT * FROM audits WHERE owner_id = ?", [userId]);
    return rows.map(rowToAudit);
  }
}
