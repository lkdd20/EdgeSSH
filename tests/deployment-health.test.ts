import assert from 'node:assert/strict';
import { test } from 'node:test';
import { verifyGithubDeployment } from '../scripts/deployment-health.ts';

const hostname = 'ssh.example.com';
const clientId = 'test-client';
const location = `https://github.com/login/oauth/authorize?client_id=${clientId}&redirect_uri=https%3A%2F%2F${hostname}%2Fauth%2Fcallback`;
const redirect = (target = location, cookie = '__Host-edgessh-oauth=test; Path=/; Secure; HttpOnly') =>
  new Response(null, { status: 302, headers: { Location: target, 'Set-Cookie': cookie } });

test('GitHub deployment probes only its own origin without following OAuth or calling Access', async () => {
  const calls: string[] = [];
  await verifyGithubDeployment(hostname, clientId, async (url, init) => {
    assert.equal(init?.redirect, 'manual');
    assert.equal(init?.headers, undefined);
    const request = new Request(url, init);
    const path = new URL(request.url).pathname;
    calls.push(path);
    assert.equal(new URL(request.url).origin, `https://${hostname}`);
    return path === '/auth/login' ? redirect() : new Response(null, { status: 401 });
  });
  assert.deepEqual(calls, ['/auth/login', '/api/auth/me']);
});

test('deployment rejects broken signing, wrong OAuth configuration and stale Access protection', async () => {
  for (const response of [
    Response.json({ error: '服务暂时不可用，请稍后重试。' }, { status: 500 }),
    redirect('https://team.cloudflareaccess.com/cdn-cgi/access/login'),
    redirect(location.replace(clientId, 'old-client')),
    redirect(location.replace('ssh.example.com', 'old.example.com')),
    redirect(location, ''),
    redirect('http://['),
  ]) {
    await assert.rejects(verifyGithubDeployment(hostname, clientId, async () => response), /登录入口验收失败/);
  }
});

test('deployment rejects uninitialized D1, provider mismatch and anonymous access', async () => {
  for (const status of [500, 503, 200, 302]) {
    await assert.rejects(verifyGithubDeployment(hostname, clientId, async (url) =>
      String(url).endsWith('/auth/login') ? redirect() : new Response(null, { status })),
    /工作区验收失败/);
  }
});

test('deployment network failures never expose upstream errors or cookie values', async () => {
  await assert.rejects(verifyGithubDeployment(hostname, clientId, async () => {
    throw new Error('private-client-secret');
  }), (error: Error) => /DNS/.test(error.message) && !error.message.includes('private-client-secret'));
});
