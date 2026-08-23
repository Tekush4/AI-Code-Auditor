/**
 * SEC-AUTHZ-001 — Proteção contra IDOR/BOLA (seção 17 e 28 do prompt mestre)
 * SEVERIDADE: CRITICAL
 *
 * Cenário: Usuário A não pode ler/editar uma auditoria pertencente ao Usuário B,
 * mesmo sabendo o ID do recurso.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { openDatabase } from "../../backend/src/modules/db/database.ts";
import { AuditRepository, AuthorizationError } from "../../backend/src/modules/db/repository.ts";

test("SEC-AUTHZ-001: usuário não consegue ler auditoria de outro usuário (IDOR)", () => {
  const db = openDatabase(":memory:");
  const repo = new AuditRepository(db);

  const auditId = repo.createAudit({ ownerId: "user-A", repoName: "meu-projeto" });

  // user-A consegue ler o próprio recurso
  const owned = repo.getAuditForUser(auditId, "user-A");
  assert.equal(owned.repoName, "meu-projeto");

  // user-B (atacante) tenta acessar o mesmo ID
  assert.throws(
    () => repo.getAuditForUser(auditId, "user-B"),
    AuthorizationError,
    "usuário B não deveria conseguir ler auditoria de usuário A"
  );
});

test("SEC-AUTHZ-001: usuário não consegue deletar auditoria de outro usuário", () => {
  const db = openDatabase(":memory:");
  const repo = new AuditRepository(db);
  const auditId = repo.createAudit({ ownerId: "user-A", repoName: "projeto-privado" });

  assert.throws(() => repo.deleteAuditForUser(auditId, "user-B"), AuthorizationError);

  // confirma que o recurso ainda existe (não foi deletado pelo atacante)
  const stillThere = repo.getAuditForUser(auditId, "user-A");
  assert.equal(stillThere.repoName, "projeto-privado");
});

test("SEC-AUTHZ-001: listagem de auditorias nunca retorna registros de outro usuário", () => {
  const db = openDatabase(":memory:");
  const repo = new AuditRepository(db);
  repo.createAudit({ ownerId: "user-A", repoName: "repo-A1" });
  repo.createAudit({ ownerId: "user-A", repoName: "repo-A2" });
  repo.createAudit({ ownerId: "user-B", repoName: "repo-B1" });

  const listForA = repo.listAuditsForUser("user-A");
  assert.equal(listForA.length, 2);
  assert.equal(listForA.every(a => a.repoName.startsWith("repo-A")), true);
});

test("SEC-AUTHZ-001: query usa parâmetros, não concatenação (proteção contra SQL injection)", () => {
  const db = openDatabase(":memory:");
  const repo = new AuditRepository(db);
  // tenta um payload clássico de SQL injection como se fosse um nome de repo
  const maliciousName = "x'; DROP TABLE audits; --";
  const id = repo.createAudit({ ownerId: "user-A", repoName: maliciousName });
  const result = repo.getAuditForUser(id, "user-A");
  assert.equal(result.repoName, maliciousName); // tratado como dado, não como SQL
  // tabela ainda existe e funciona
  assert.equal(repo.listAuditsForUser("user-A").length, 1);
});
