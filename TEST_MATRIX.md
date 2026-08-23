# TEST_MATRIX — AI Code Auditor

## Executado neste ambiente

| ID | Área | Resultado |
|---|---|---|
| SEC-AUTH-001 | Password/session | PASS |
| SEC-AUTHZ-001 | IDOR/ownership | PASS |
| SEC-API-001 | HTTP hardening/rate limit/payload | PASS |
| SEC-UPLOAD-001 | Import/symlink/limits | PASS |
| SEC-SAST-001 | AST SAST inicial | PASS |
| SEC-SECRET-001 / SECRET-002 | Secret masking/detection | PASS |
| SEC-DEPS-001 | Dependency parser/providers | PASS |
| SEC-CORRELATION-001 | Correlation | PASS |
| SEC-RISK-001 | Risk | PASS |
| SEC-REPORT-001 | Reports | PASS |
| FASE-10 | Architecture Analyzer | PASS |
| FASE-11 | Performance Analyzer | PASS |
| FASE-12/PIPELINE | AI provider + pipeline | PASS |
| SEC-ANALYSIS-AUTHZ-001 | Cross-user analysis isolation | PASS |

Total executado após as mudanças: **69 testes, 69 passando, 0 falhando**.

## Typecheck
`tsc --noEmit`: PASS.

## Não testado / indisponível
- Docker daemon: **NOT AVAILABLE** neste ambiente; Dockerfile/compose foram criados, mas a imagem não foi declarada como testada.
- GitHub Actions runner: **NOT TESTED** localmente.
- Provedores externos de vulnerabilidade/IA: **NOT TESTED** contra serviços externos.
- ZIP real: **PARTIAL** — o importador de diretório é funcional e seguro contra symlink/path escape; importação de ZIP continua pendente.

## Self-audit
O próprio pipeline foi executado sobre o projeto e produziu **15 findings ativos**, com score heurístico máximo de 100. Parte dos achados vem de fixtures de testes e do próprio código de análise (por exemplo, padrões de secret presentes deliberadamente nos testes); eles não foram ocultados.
