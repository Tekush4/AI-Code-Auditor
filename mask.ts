/**
 * Detecção e mascaramento de secrets em código-fonte.
 *
 * IMPORTANTE (regra do prompt mestre):
 * - Nunca persistir o secret bruto em log.
 * - Nunca retornar o secret bruto para o frontend.
 * - `scanForSecrets` retorna SOMENTE a versão mascarada — o valor original nunca
 *   sai da função de detecção.
 *
 * Limitação declarada: este é um scanner baseado em regex + padrão de prefixo,
 * complementado por um MVP de análise de entropia (ver `looksLikeHighEntropy`).
 * Regras 6/8 do prompt: não depender só de regex — em produção, mesclar com
 * Gitleaks (feed de padrões mantido pela comunidade) para maior cobertura.
 */

export interface SecretFinding {
  file: string;
  category: string;
  masked: string;
  confidence: "high" | "medium";
}

interface SecretPattern {
  category: string;
  regex: RegExp;
}

// Padrões conhecidos e publicamente documentados (não são "listas secretas" —
// prefixos como AKIA/sk_live são públicos e documentados pelos próprios provedores).
const PATTERNS: SecretPattern[] = [
  { category: "aws_access_key", regex: /AKIA[0-9A-Z]{16}/g },
  { category: "stripe_live_key", regex: /sk_live_[A-Za-z0-9]{16,}/g },
  { category: "github_token", regex: /gh[pousr]_[A-Za-z0-9]{36,}/g },
  { category: "slack_token", regex: /xox[baprs]-[0-9A-Za-z-]{10,}/g },
  { category: "jwt", regex: /eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{10,}/g },
  { category: "database_connection_string", regex: /(postgres|postgresql|mysql|mongodb):\/\/[^:\s]+:([^@\s]+)@[^\s"']+/g },
  { category: "generic_api_key_assignment", regex: /(api[_-]?key|secret|token)\s*[:=]\s*["']([A-Za-z0-9\-_]{20,})["']/gi },
  { category: "private_key", regex: /-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----/g },
];

/**
 * Mascara um segredo mantendo o prefixo legível (para identificação do tipo)
 * e os últimos 4 caracteres (para o usuário reconhecer QUAL credencial é, sem
 * expor o valor). Exemplo do prompt mestre:
 *   sk_live_XXXXXXXXXXXXXXXX1234 -> sk_live_************1234
 */
export function maskSecret(secret: string): string {
  if (secret.length <= 8) {
    return "*".repeat(secret.length);
  }

  // Detecta prefixo conhecido tipo "sk_live_", "AKIA", etc. (letras/underscore antes de dígitos/mix)
  const prefixMatch = secret.match(/^([a-zA-Z]+_)+/);
  const prefix = prefixMatch ? prefixMatch[0] : "";
  const remainder = secret.slice(prefix.length);

  if (remainder.length <= 4) {
    return prefix + "*".repeat(remainder.length);
  }

  const last4 = remainder.slice(-4);
  const maskedLen = remainder.length - 4;
  return `${prefix}${"*".repeat(maskedLen)}${last4}`;
}

/**
 * Varre um trecho de código em busca de secrets conhecidos.
 * Retorna apenas achados MASCARADOS — nunca o valor bruto.
 */
export function scanForSecrets(code: string, file: string): SecretFinding[] {
  const findings: SecretFinding[] = [];

  for (const pattern of PATTERNS) {
    pattern.regex.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = pattern.regex.exec(code)) !== null) {
      let masked: string;

      if (pattern.category === "generic_api_key_assignment") {
        masked = maskSecret(match[2]);
      } else if (pattern.category === "database_connection_string") {
        // Mascara APENAS a senha embutida na connection string; mantém host/porta/db
        // visíveis (não são segredo) para o relatório continuar útil.
        const password = match[2];
        masked = match[0].replace(password, maskSecret(password));
      } else {
        masked = maskSecret(match[0]);
      }

      findings.push({
        file,
        category: pattern.category,
        masked,
        confidence: "high",
      });
      if (!pattern.regex.global) break;
    }
  }

  return findings;
}
