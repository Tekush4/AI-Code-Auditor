/**
 * SEC-API-001 — Segurança básica da API HTTP (Fase 5)
 * Cobre: headers de segurança, CORS, limite de payload, rate limiting,
 * autenticação obrigatória em rota protegida, correlation ID, erro sem stack trace.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "../../backend/src/modules/http/server.ts";
import { openDatabase } from "../../backend/src/modules/db/database.ts";

async function withServer(fn: (base: string) => Promise<void>) {
  const db = openDatabase(":memory:");
  const server = createServer(db);
  await new Promise<void>(resolve => server.listen(0, resolve));
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : 0;
  try {
    await fn(`http://127.0.0.1:${port}`);
  } finally {
    server.close();
  }
}

test("SEC-API-001: /health responde 200 sem autenticação", async () => {
  await withServer(async base => {
    const res = await fetch(`${base}/health`);
    assert.equal(res.status, 200);
  });
});

test("SEC-API-001: resposta inclui headers de segurança (nosniff, no frame, HSTS-like)", async () => {
  await withServer(async base => {
    const res = await fetch(`${base}/health`);
    assert.equal(res.headers.get("x-content-type-options"), "nosniff");
    assert.equal(res.headers.get("x-frame-options"), "DENY");
    assert.equal(res.headers.get("referrer-policy"), "no-referrer");
  });
});

test("SEC-API-001: toda resposta tem um correlation id", async () => {
  await withServer(async base => {
    const res = await fetch(`${base}/health`);
    assert.ok(res.headers.get("x-correlation-id"));
  });
});

test("SEC-API-001: GET /projects sem token retorna 401", async () => {
  await withServer(async base => {
    const res = await fetch(`${base}/projects`);
    assert.equal(res.status, 401);
    const body = await res.json();
    assert.equal(body.stack, undefined, "resposta de erro nunca deve conter stack trace");
  });
});

test("SEC-API-001: payload maior que o limite é rejeitado com 413", async () => {
  await withServer(async base => {
    const bigBody = "x".repeat(2_000_000); // 2MB
    const res = await fetch(`${base}/auth/register`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ username: "a", password: bigBody }),
    });
    assert.equal(res.status, 413);
  });
});

test("SEC-API-001: rate limiting bloqueia após muitas tentativas de login", async () => {
  await withServer(async base => {
    let lastStatus = 0;
    for (let i = 0; i < 12; i++) {
      const res = await fetch(`${base}/auth/login`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ username: "ghost", password: "wrong-pass" }),
      });
      lastStatus = res.status;
    }
    assert.equal(lastStatus, 429);
  });
});

test("SEC-API-001: fluxo completo register -> login -> me autenticado", async () => {
  await withServer(async base => {
    const reg = await fetch(`${base}/auth/register`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ username: "alice", password: "Sup3rSecret!" }),
    });
    assert.equal(reg.status, 201);

    const login = await fetch(`${base}/auth/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ username: "alice", password: "Sup3rSecret!" }),
    });
    assert.equal(login.status, 200);
    const { token } = await login.json();
    assert.ok(token);

    const me = await fetch(`${base}/me`, { headers: { authorization: `Bearer ${token}` } });
    assert.equal(me.status, 200);
    const meBody = await me.json();
    assert.equal(meBody.username, "alice");
    assert.equal(meBody.passwordHash, undefined, "hash de senha nunca deve ser exposto na API");
  });
});

test("SEC-API-001: login com usuário inexistente e senha errada retornam a mesma mensagem (anti-enumeration)", async () => {
  await withServer(async base => {
    const r1 = await fetch(`${base}/auth/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ username: "nao-existe-" + Date.now(), password: "qualquer" }),
    });
    const b1 = await r1.json();

    const reg = await fetch(`${base}/auth/register`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ username: "bob" + Date.now(), password: "Sup3rSecret!" }),
    });
    const regBody = await reg.json();

    const r2 = await fetch(`${base}/auth/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ username: regBody.username ?? "bob", password: "senha-errada" }),
    });
    const b2 = await r2.json();

    assert.equal(r1.status, r2.status);
    assert.equal(b1.error, b2.error);
  });
});
