/**
 * UserRepository + Session — base de autenticação para a API HTTP (Fase 5).
 *
 * Anti account-enumeration (seção 16 do prompt): login sempre retorna a mesma
 * mensagem genérica, seja usuário inexistente ou senha errada.
 */
import { randomUUID, randomBytes } from "node:crypto";
import type { Database } from "../db/database.ts";
import { hashPassword, verifyPassword } from "./password.ts";

export class InvalidCredentialsError extends Error {
  constructor() {
    super("Credenciais inválidas.");
    this.name = "InvalidCredentialsError";
  }
}

export class DuplicateUserError extends Error {
  constructor() {
    super("Não foi possível concluir o registro.");
    this.name = "DuplicateUserError";
  }
}

export function ensureAuthTables(db: Database): void {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL
    );
  `);
}

interface UserRow {
  id: string;
  username: string;
  password_hash: string;
  created_at: string;
}

export class UserRepository {
  constructor(private db: Database) {
    ensureAuthTables(db);
  }

  async register(username: string, password: string): Promise<string> {
    if (!username || username.length < 3) throw new Error("username inválido");
    if (!password || password.length < 8) throw new Error("senha deve ter ao menos 8 caracteres");

    const existing = this.db.get<UserRow>("SELECT * FROM users WHERE username = ?", [username]);
    if (existing) throw new DuplicateUserError();

    const id = randomUUID();
    const passwordHash = await hashPassword(password);
    this.db.run(
      "INSERT INTO users (id, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
      [id, username, passwordHash, new Date().toISOString()]
    );
    return id;
  }

  /** Retorna userId em caso de sucesso. Sempre a mesma exceção em caso de falha (anti-enumeration). */
  async login(username: string, password: string): Promise<string> {
    const row = this.db.get<UserRow>("SELECT * FROM users WHERE username = ?", [username]);
    if (!row) {
      // Ainda assim computamos um hash "fantasma" para igualar o tempo de resposta
      // entre "usuário não existe" e "senha errada" (mitigação de timing attack).
      await verifyPassword(password, "scrypt$00$00");
      throw new InvalidCredentialsError();
    }
    const valid = await verifyPassword(password, row.password_hash);
    if (!valid) throw new InvalidCredentialsError();
    return row.id;
  }
}

interface SessionRow {
  token: string;
  user_id: string;
  created_at: string;
  expires_at: string;
}

const SESSION_TTL_MS = 1000 * 60 * 60 * 2; // 2 horas

export class SessionRepository {
  constructor(private db: Database) {
    ensureAuthTables(db);
  }

  create(userId: string): string {
    const token = randomBytes(32).toString("hex"); // opaco, alta entropia
    const now = new Date();
    const expires = new Date(now.getTime() + SESSION_TTL_MS);
    this.db.run(
      "INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
      [token, userId, now.toISOString(), expires.toISOString()]
    );
    return token;
  }

  /** Retorna o userId se o token for válido e não expirado; null caso contrário. */
  validate(token: string): string | null {
    if (!token) return null;
    const row = this.db.get<SessionRow>("SELECT * FROM sessions WHERE token = ?", [token]);
    if (!row) return null;
    if (new Date(row.expires_at).getTime() < Date.now()) {
      this.revoke(token);
      return null;
    }
    return row.user_id;
  }

  revoke(token: string): void {
    this.db.run("DELETE FROM sessions WHERE token = ?", [token]);
  }
}
