/**
 * Rate limiter simples (fixed window) em memória.
 * Limitação declarada: em produção multi-instância, isso precisa ser compartilhado
 * (ex: Redis). Para um único processo (MVP), memória é suficiente e real (não mockado).
 */
export class RateLimiter {
  private hits = new Map<string, { count: number; windowStart: number }>();

  constructor(private maxAttempts: number, private windowMs: number) {}

  /** Retorna true se a requisição é permitida; false se o limite foi excedido. */
  check(key: string): boolean {
    const now = Date.now();
    const entry = this.hits.get(key);

    if (!entry || now - entry.windowStart > this.windowMs) {
      this.hits.set(key, { count: 1, windowStart: now });
      return true;
    }

    if (entry.count >= this.maxAttempts) {
      return false;
    }

    entry.count += 1;
    return true;
  }

  reset(key: string): void {
    this.hits.delete(key);
  }
}
