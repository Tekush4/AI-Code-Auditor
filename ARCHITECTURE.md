# ARCHITECTURE — AI Code Auditor

## Fluxo atual

Frontend → HTTP API → Authorization → AnalysisPipeline → Import → Language Detection → SAST + Secrets + Dependencies + Architecture + Performance + AI → Normalize → Correlation → Risk → Reports → SQLite.

## Módulos principais
- `analyzers/architecture`: linguagens, frameworks, módulos, imports, dependências externas, componentes, relações, ciclos e riscos.
- `analyzers/performance`: heurísticas de arquivo grande, loops aninhados, muitas chamadas de banco e I/O síncrono.
- `ai`: `AIProvider`, `MockAIProvider`, adapter preparado e redaction antes da IA.
- `analysis`: orquestração e persistência das análises.
- `db`: SQLite local com ownership por usuário.
- `http`: autenticação, autorização, endpoints e frontend estático.

## Contrato da IA
Código e findings passam por redaction antes do provider. O provider não recebe secrets conhecidos, tokens, chaves privadas ou credenciais de banco em texto. O resultado da IA é tratado como evidência de baixa confiança relativa: não confirma sozinho uma vulnerabilidade.

## Persistência
`audits`, `analyses`, `analysis_findings`, `reports`, `users`, `sessions`. Findings e relatórios são associados ao `owner_id` e todos os acessos de análise verificam ownership.

## API de análise
- `POST /projects/:id/analyze`
- `GET /projects/:id/analyses`
- `GET /analyses/:id`
- `GET /analyses/:id/findings`
- `GET /analyses/:id/report`

O caminho local usado pela análise precisa estar dentro de `AICA_PROJECT_ROOT`.

## Segurança
- Passwords com scrypt e salt aleatório.
- Bearer sessions opacas com expiração.
- Rate limit de login.
- Payload máximo de 1 MB.
- Headers de segurança e correlation ID.
- Ownership check no backend.
- Queries parametrizadas.
- Secrets mascarados.
- Importador rejeita symlinks que escapem da base e possui limites de arquivos/tamanho.

## Limitações
Não há garantia de cobertura total. Architecture/Performance são heurísticos. Dependências transitivas ainda não são analisadas. ZIP real e integrações externas permanecem parciais/não testadas.
