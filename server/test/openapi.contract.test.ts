import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { after, before, describe, it } from 'node:test';
import { parse } from 'yaml';
import { AGENT_PREFIX } from '../src/agent/server.ts';
import { API_PREFIX, OPENAPI_PATH, type RegisteredRoute } from '../src/app.ts';
import { startAgentServer, type AgentServerHandle } from './agent-helpers.ts';
import { setup, type TestCtx } from './helpers.ts';

const AGENT_SPEC = fileURLToPath(new URL('../openapi-agent.yaml', import.meta.url));
const METHODS = ['get', 'post', 'put', 'patch', 'delete'];

type Op = { 'x-permission'?: string; tags?: string[]; security?: unknown[] };

function documented(specPath: string): Set<string> {
  const spec = parse(readFileSync(specPath, 'utf8'));
  const out = new Set<string>();
  for (const [path, item] of Object.entries<Record<string, unknown>>(spec.paths)) {
    for (const m of METHODS) if (item[m]) out.add(`${m.toUpperCase()} ${path}`);
  }
  return out;
}

function implemented(routes: RegisteredRoute[], prefix: string): Set<string> {
  return new Set(
    routes
      .filter((r) => r.url.startsWith(`${prefix}/`))
      .map((r) => `${r.method} ${r.url.slice(prefix.length).replace(/:(\w+)/g, '{$1}')}`),
  );
}

function assertSame(impl: Set<string>, docs: Set<string>, spec: string) {
  assert.deepEqual([...impl].filter((r) => !docs.has(r)), [], `routes missing in ${spec}`);
  assert.deepEqual([...docs].filter((r) => !impl.has(r)), [], `operations in ${spec} without implementation`);
}

/**
 * The OpenAPI files are the single source of truth: every route must be documented
 * and every documented operation must be implemented.
 */
describe('OpenAPI contract', () => {
  let ctx: TestCtx;
  let agentSrv: AgentServerHandle;
  before(async () => {
    ctx = await setup();
    agentSrv = await startAgentServer(ctx);
  });
  after(async () => {
    await agentSrv.close();
    await ctx.close();
  });

  it('public API routes and openapi.yaml match exactly', () => {
    assertSame(implemented(ctx.app.registeredRoutes, API_PREFIX), documented(OPENAPI_PATH), 'openapi.yaml');
  });

  it('agent endpoint routes and openapi-agent.yaml match exactly', () => {
    assertSame(implemented(agentSrv.app.registeredRoutes, AGENT_PREFIX), documented(AGENT_SPEC), 'openapi-agent.yaml');
  });

  it('every protected operation declares x-permission', () => {
    const spec = parse(readFileSync(OPENAPI_PATH, 'utf8'));
    for (const [path, item] of Object.entries<Record<string, Op>>(spec.paths)) {
      for (const [m, op] of Object.entries(item)) {
        if (!METHODS.includes(m)) continue;
        const isPublic = Array.isArray(op.security) && op.security.length === 0;
        if (isPublic || op.tags?.[0] === 'auth') continue;
        assert.ok(op['x-permission'], `${m.toUpperCase()} ${path} lacks x-permission`);
      }
    }
  });
});
