# syntax=docker/dockerfile:1
FROM node:22-bookworm-slim

WORKDIR /app

# 1) Copia apenas os manifests primeiro (cache de camadas do Docker).
COPY package.json package-lock.json* ./

# 2) Usa `npm ci` quando existir um package-lock.json compatível (build
#    reprodutível); cai para `npm install` quando não existir lockfile.
#    Instala TODAS as dependências de "dependencies" — nada de devDependencies
#    em produção. "typescript" e "tsx" já estão em "dependencies" porque o
#    pipeline de SAST usa o TypeScript Compiler API em tempo de execução
#    (backend/src/modules/sast/engine.ts) e o start real do projeto roda a
#    aplicação via tsx (sem etapa de build/transpilação).
RUN if [ -f package-lock.json ]; then \
      npm ci --omit=dev; \
    else \
      npm install --omit=dev; \
    fi

# 3) Copia o restante do repositório real (respeitando .dockerignore).
#    Não assumimos nomes fixos de subpastas: isso evita quebra de build caso
#    a estrutura do repositório mude (ex.: "COPY frontend ./frontend" falhando
#    quando essa pasta não existir no contexto de build real do Render).
COPY . .

ENV NODE_ENV=production \
    PORT=3000 \
    AICA_DB_PATH=/data/aica.sqlite \
    AICA_PROJECT_ROOT=/workspace

# 4) Cria os diretórios de dados/workspace e ajusta o dono para o usuário
#    não-root "node" (já existente na imagem node:*-bookworm-slim) ANTES de
#    trocar de usuário. Sem isso, gravar o SQLite em /data falharia por
#    permissão quando o processo já não é mais root.
RUN mkdir -p /data /workspace && chown -R node:node /app /data /workspace

USER node

VOLUME ["/data","/workspace"]

# Apenas documental — o servidor sempre escuta na porta definida por $PORT
# (fornecida pelo ambiente em runtime, ex.: Render), não necessariamente 3000.
EXPOSE 3000

# Usa $PORT em runtime (com 3000 como fallback local) e a rota /healthz.
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD node -e "const p=process.env.PORT||3000;fetch('http://127.0.0.1:'+p+'/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

# Respeita o script real de start do package.json ("start": "tsx backend/src/server.ts"),
# em vez de duplicar o comando aqui — se o script mudar, o Dockerfile não precisa mudar.
CMD ["npm", "start"]
