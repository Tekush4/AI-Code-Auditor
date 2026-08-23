/**
 * Password hashing — usa scrypt (node:crypto), uma primitiva padrão e revisada.
 * NUNCA implementamos algoritmo criptográfico próprio (regra 13 do prompt mestre).
 *
 * Formato do hash armazenado: scrypt$<saltHex>$<hashHex>
 * Parâmetros de custo seguem recomendação da documentação oficial do Node.js
 * para scrypt (N=16384, r=8, p=1, keylen=64), revisar periodicamente contra
 * OWASP Password Storage Cheat Sheet.
 */
import { randomBytes, scrypt as scryptCallback, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";

const scrypt = promisify(scryptCallback) as unknown as (password: string | Buffer, salt: string | Buffer, keylen: number, options: { N: number; r: number; p: number; maxmem: number }) => Promise<Buffer>;

const SCRYPT_KEYLEN = 64;
const SCRYPT_OPTIONS = { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

export async function hashPassword(plainPassword: string): Promise<string> {
  if (typeof plainPassword !== "string" || plainPassword.length === 0) {
    throw new Error("password must be a non-empty string");
  }
  const salt = randomBytes(16);
  const derivedKey = (await scrypt(plainPassword, salt, SCRYPT_KEYLEN, SCRYPT_OPTIONS)) as Buffer;
  return `scrypt$${salt.toString("hex")}$${derivedKey.toString("hex")}`;
}

export async function verifyPassword(plainPassword: string, storedHash: string): Promise<boolean> {
  const parts = storedHash.split("$");
  if (parts.length !== 3 || parts[0] !== "scrypt") {
    // Formato inesperado — nunca lançar erro que vaze detalhes ao chamador (anti account enumeration)
    return false;
  }
  const [, saltHex, hashHex] = parts;
  const salt = Buffer.from(saltHex, "hex");
  const storedKey = Buffer.from(hashHex, "hex");
  const derivedKey = (await scrypt(plainPassword, salt, storedKey.length, SCRYPT_OPTIONS)) as Buffer;
  // timingSafeEqual evita timing attacks na comparação
  if (derivedKey.length !== storedKey.length) return false;
  return timingSafeEqual(derivedKey, storedKey);
}
