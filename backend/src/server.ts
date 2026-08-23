/**
 * Servidor HTTP — Fase 5.
 * Usa node:http puro (sem Express/Fastify, indisponíveis sem rede neste sandbox).
 * Implementa: headers de segurança, CORS, correlation id, limite de payload,
 * rate limiting, autenticação via Bearer token, tratamento de erro sem vazar stack trace.
 */
import { createServer as createHttpServer, type Server } from "node:http";
import { randomUUID } from "node:crypto";
import { Router, type RequestContext } from "./router.ts";
import type { Database } from "../db/database.ts";
import { UserRepository, SessionRepository, InvalidCredentialsError, DuplicateUserError } from "../auth/users.ts";
import { AuditRepository, AuthorizationError } from "../db/repository.ts";
import { RateLimiter } from "../auth/rateLimiter.ts";
import { AnalysisPipeline } from "../analysis/pipeline.ts";
import { AnalysisRepository } from "../analysis/repository.ts";
import path from "node:path";
import { readFileSync } from "node:fs";

const MAX_BODY_BYTES = 1_000_000; // 1MB — protege contra payload abuse (seção 18 do prompt)

function applySecurityHeaders(res: import("node:http").ServerResponse) {
  res.setHeader("x-content-type-options", "nosniff");
  res.setHeader("x-frame-options", "DENY");
  res.setHeader("referrer-policy", "no-referrer");
  res.setHeader("strict-transport-security", "max-age=63072000; includeSubDomains");
  // CORS deliberadamente restritivo por padrão — sem origin curinga (regra 18 do prompt)
  res.setHeader("access-control-allow-origin", "null");
}

export function createServer(db: Database): Server {
  const users = new UserRepository(db);
  const sessions = new SessionRepository(db);
  const projects = new AuditRepository(db);
  const loginLimiter = new RateLimiter(5, 60_000);
  const analyses = new AnalysisRepository(db);
  const pipeline = new AnalysisPipeline();

  const router = new Router();

  router.get("/health", ctx => ctx.json({ status: "ok" }));
  // Alias para /health: alguns orquestradores/monitoramentos (ex.: convenção
  // usada no deploy do Render) esperam especificamente "/healthz".
  // Não substitui /health (mantido por compatibilidade com o que já existe).
  router.get("/healthz", ctx => ctx.json({ status: "ok" }));
  router.get("/ready", ctx => ctx.json({ status: "ready" }));

  router.post("/auth/register", async ctx => {
    const body = ctx.body as { username?: string; password?: string };
    try {
      const id = await users.register(body.username ?? "", body.password ?? "");
      ctx.status(201).json({ id, username: body.username });
    } catch (err) {
      if (err instanceof DuplicateUserError) {
        ctx.status(409).json({ error: "Não foi possível concluir o registro." });
        return;
      }
      ctx.status(400).json({ error: "Dados de registro inválidos." });
    }
  });

  router.post("/auth/login", async ctx => {
    const body = ctx.body as { username?: string; password?: string };
    const key = `login:${body.username ?? "unknown"}`;
    if (!loginLimiter.check(key)) {
      ctx.status(429).json({ error: "Muitas tentativas. Tente novamente mais tarde." });
      return;
    }
    try {
      const userId = await users.login(body.username ?? "", body.password ?? "");
      const token = sessions.create(userId);
      ctx.json({ token });
    } catch (err) {
      // Mesma mensagem para "não existe" e "senha errada" (anti account enumeration)
      ctx.status(401).json({ error: "Usuário ou senha inválidos." });
    }
  });

  router.post("/auth/logout", ctx => {
    const auth = ctx.headers.authorization as string | undefined;
    const token = auth?.startsWith("Bearer ") ? auth.slice(7) : undefined;
    if (token) sessions.revoke(token);
    ctx.json({ status: "logged_out" });
  });

  router.get("/me", ctx => {
    if (!ctx.userId) {
      ctx.status(401).json({ error: "Não autenticado." });
      return;
    }
    // Nunca expor password_hash — buscamos só o necessário
    const row = (db as unknown as { get: Database["get"] }).get<{ id: string; username: string }>(
      "SELECT id, username FROM users WHERE id = ?",
      [ctx.userId]
    );
    ctx.json({ id: row?.id, username: row?.username });
  });

  router.post("/projects", ctx => {
    if (!ctx.userId) { ctx.status(401).json({ error: "Não autenticado." }); return; }
    const body = ctx.body as { repoName?: string; sourcePath?: string };
    if (!body.repoName) { ctx.status(400).json({ error: "repoName é obrigatório." }); return; }
    const id = projects.createAudit({ ownerId: ctx.userId, repoName: body.repoName, sourcePath: body.sourcePath });
    ctx.status(201).json({ id });
  });

  router.get("/projects", ctx => {
    if (!ctx.userId) { ctx.status(401).json({ error: "Não autenticado." }); return; }
    ctx.json({ projects: projects.listAuditsForUser(ctx.userId) });
  });

  router.get("/projects/:id", ctx => {
    if (!ctx.userId) { ctx.status(401).json({ error: "Não autenticado." }); return; }
    try {
      const project = projects.getAuditForUser(ctx.params.id, ctx.userId);
      ctx.json(project);
    } catch (err) {
      if (err instanceof AuthorizationError) {
        // 404 em vez de 403: não revela se o recurso existe para outro usuário
        ctx.status(404).json({ error: "Recurso não encontrado." });
        return;
      }
      throw err;
    }
  });

  router.post("/projects/:id/analyze", async ctx => {
    if (!ctx.userId) { ctx.status(401).json({ error: "Não autenticado." }); return; }
    const project = (() => { try { return projects.getAuditForUser(ctx.params.id, ctx.userId!); } catch { return null; } })();
    if (!project) { ctx.status(404).json({ error: "Recurso não encontrado." }); return; }
    const body = (ctx.body ?? {}) as { sourcePath?: string };
    const sourcePath = body.sourcePath ?? project.sourcePath;
    if (!sourcePath) { ctx.status(400).json({ error: "sourcePath é obrigatório para análise local." }); return; }
    const root = path.resolve(process.env.AICA_PROJECT_ROOT ?? process.cwd());
    const resolved = path.resolve(sourcePath);
    const rel = path.relative(root, resolved);
    if (rel.startsWith("..") || path.isAbsolute(rel)) { ctx.status(400).json({ error: "sourcePath fora do diretório permitido." }); return; }
    try { const result = await pipeline.run(project.id, project.repoName, resolved); analyses.save(ctx.userId!, result); ctx.status(201).json({ analysisId: result.id, status: result.status }); }
    catch { ctx.status(500).json({ error: "Falha ao executar análise." }); }
  });

  router.get("/projects/:id/analyses", ctx => {
    if (!ctx.userId) { ctx.status(401).json({ error: "Não autenticado." }); return; }
    try { projects.getAuditForUser(ctx.params.id, ctx.userId); } catch { ctx.status(404).json({ error: "Recurso não encontrado." }); return; }
    ctx.json({ analyses: analyses.list(ctx.params.id, ctx.userId) });
  });

  router.get("/analyses/:id", ctx => {
    if (!ctx.userId) { ctx.status(401).json({ error: "Não autenticado." }); return; }
    const result = analyses.get(ctx.params.id, ctx.userId); if (!result) { ctx.status(404).json({ error: "Recurso não encontrado." }); return; } ctx.json(result);
  });
  router.get("/analyses/:id/findings", ctx => {
    if (!ctx.userId) { ctx.status(401).json({ error: "Não autenticado." }); return; }
    const result = analyses.findings(ctx.params.id, ctx.userId); if (!result) { ctx.status(404).json({ error: "Recurso não encontrado." }); return; } ctx.json({ findings: result });
  });
  router.get("/analyses/:id/report", ctx => {
    if (!ctx.userId) { ctx.status(401).json({ error: "Não autenticado." }); return; }
    const result = analyses.report(ctx.params.id, ctx.userId); if (!result) { ctx.status(404).json({ error: "Recurso não encontrado." }); return; } ctx.json(result);
  });

  router.delete("/projects/:id", ctx => {
    if (!ctx.userId) { ctx.status(401).json({ error: "Não autenticado." }); return; }
    try {
      projects.deleteAuditForUser(ctx.params.id, ctx.userId);
      ctx.status(204).json(undefined);
    } catch (err) {
      if (err instanceof AuthorizationError) {
        ctx.status(404).json({ error: "Recurso não encontrado." });
        return;
      }
      throw err;
    }
  });

  const server = createHttpServer((req, res) => {
    const correlationId = randomUUID();
    res.setHeader("x-correlation-id", correlationId);
    applySecurityHeaders(res);

    if (req.method === "OPTIONS") {
      res.writeHead(204);
      res.end();
      return;
    }

    const chunks: Buffer[] = [];
    let totalSize = 0;
    let rejected = false;

    req.on("data", (chunk: Buffer) => {
      if (rejected) return;
      totalSize += chunk.length;
      if (totalSize > MAX_BODY_BYTES) {
        rejected = true;
        res.writeHead(413, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "Payload muito grande." }));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });

    req.on("end", async () => {
      if (rejected) return;

      let parsedBody: unknown = {};
      const raw = Buffer.concat(chunks).toString("utf8");
      if (raw) {
        try {
          parsedBody = JSON.parse(raw);
        } catch {
          res.writeHead(400, { "content-type": "application/json" });
          res.end(JSON.stringify({ error: "JSON inválido." }));
          return;
        }
      }

      const url = new URL(req.url ?? "/", "http://localhost");
      if (req.method === "GET" && ["/", "/index.html", "/app.js", "/styles.css"].includes(url.pathname)) {
        const file = url.pathname === "/" || url.pathname === "/index.html" ? "index.html" : url.pathname.slice(1);
        const mime:Record<string,string>={"index.html":"text/html; charset=utf-8","app.js":"text/javascript; charset=utf-8","styles.css":"text/css; charset=utf-8"};
        try { res.writeHead(200,{"content-type":mime[file]}); res.end(readFileSync(path.resolve(process.cwd(),"frontend",file))); } catch { res.writeHead(404); res.end(); }
        return;
      }
      const match = router.match(req.method ?? "GET", url.pathname);

      if (!match) {
        res.writeHead(404, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "Rota não encontrada." }));
        return;
      }

      // Autenticação: extrai userId do Bearer token, se houver
      const authHeader = req.headers.authorization;
      const token = typeof authHeader === "string" && authHeader.startsWith("Bearer ")
        ? authHeader.slice(7)
        : undefined;
      const userId = token ? sessions.validate(token) ?? undefined : undefined;

      let statusCode = 200;
      const ctx: RequestContext = {
        method: req.method ?? "GET",
        path: url.pathname,
        params: match.params,
        query: url.searchParams,
        headers: req.headers as Record<string, string | string[] | undefined>,
        body: parsedBody,
        userId,
        correlationId,
        status(code: number) {
          statusCode = code;
          return ctx;
        },
        json(payload: unknown) {
          if (res.headersSent) return;
          res.writeHead(statusCode, { "content-type": "application/json" });
          res.end(payload === undefined ? "" : JSON.stringify(payload));
        },
      };

      try {
        await match.handler(ctx);
      } catch (err) {
        // Nunca vazar stack trace ou detalhes internos na resposta (regra 18 do prompt)
        if (!res.headersSent) {
          res.writeHead(500, { "content-type": "application/json" });
          res.end(JSON.stringify({ error: "Erro interno.", correlationId }));
        }
      }
    });
  });

  return server;
  }
