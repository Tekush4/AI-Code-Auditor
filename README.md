# AI Code Auditor

Plataforma funcional de auditoria automatizada de projetos, preservando os engines existentes e conectando Import → SAST → Secrets → Dependencies → Architecture → Performance → AI → Correlation → Risk → Report.

## Estado implementado
- Fases 1, 3-15 preservadas/auditadas.
- Fases 10 Architecture Analyzer, 11 Performance Analyzer e 12 AI Provider implementadas.
- Pipeline persistente e endpoint `POST /projects/:id/analyze`.
- Endpoints de análises, findings e reports com isolamento por usuário.
- Frontend web funcional servido pelo backend.
- CI/CD, Docker e documentação atualizados.

## Executar
Node.js 22+. `npm install`, depois `npm run typecheck`, `npm run test:security` e `npm start`. A interface fica em `http://localhost:3000`.

Para análise local, defina `AICA_PROJECT_ROOT` como diretório raiz permitido e informe esse caminho ao criar o projeto. O pipeline não aceita caminhos fora dessa raiz.

## Integrações externas
O build local usa fixtures de dependências quando selecionado pelo pipeline e não finge consultas externas. O adapter de IA externo é uma interface preparada; o `MockAIProvider` é o provider executável localmente.

## Limitações
Heurísticas de arquitetura/performance não equivalem a prova de vulnerabilidade ou profiling. ZIP direto ainda é uma limitação do importador; a proteção existente para diretórios e symlinks permanece ativa. Não há garantia de cobertura total.
