# THREAT MODEL — AI Code Auditor

## Ativos
Código-fonte importado, credenciais/secrets detectados, senhas, tokens de sessão, findings, relatórios e metadados de projetos.

## Ameaças tratadas
- IDOR/BOLA entre usuários.
- Account enumeration em login.
- Brute force básico via rate limit.
- SQL injection em persistência.
- Path traversal e symlink escape no import.
- Payload abuse.
- Vazamento de secrets em findings/relatórios.
- Exposição de stack trace.
- Acesso do provider de IA a secrets antes da redaction.
- Acesso de `sourcePath` fora da raiz autorizada.

## Controles
Ownership é verificado antes de cada leitura de projeto/análise. Secrets são mascarados antes da persistência de findings. A IA recebe apenas contexto redigido. O banco não é acessado diretamente pelo frontend.

## Riscos residuais
- Scanner SAST não possui taint tracking completo.
- Heurísticas de performance/arquitetura podem gerar falsos positivos.
- Fixture provider não substitui uma base CVE online.
- ZIP ainda não é extraído pelo importador.
- Sessões em memória para rate limiter não são adequadas para múltiplas instâncias sem armazenamento compartilhado.
- Docker e CI foram escritos, mas não executados neste ambiente.
