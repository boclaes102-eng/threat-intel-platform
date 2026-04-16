import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { buildServer } from '../../../src/api/server';

let server: FastifyInstance;

beforeAll(async () => {
  server = await buildServer();
  await server.ready();
});

afterAll(async () => {
  await server.close();
});

describe('POST /api/v1/auth/register', () => {
  it('registers a new user and returns JWT', async () => {
    const res = await server.inject({
      method: 'POST',
      url: '/api/v1/auth/register',
      payload: { email: 'test@example.com', password: 'password123' },
    });

    expect(res.statusCode).toBe(201);
    const body = res.json();
    expect(body.accessToken).toBeTruthy();
    expect(body.user.email).toBe('test@example.com');
    expect(body.user.passwordHash).toBeUndefined();
  });

  it('returns 409 if email is already registered', async () => {
    const payload = { email: 'duplicate@example.com', password: 'password123' };
    await server.inject({ method: 'POST', url: '/api/v1/auth/register', payload });
    const res = await server.inject({ method: 'POST', url: '/api/v1/auth/register', payload });

    expect(res.statusCode).toBe(409);
  });

  it('returns 400 for invalid email', async () => {
    const res = await server.inject({
      method: 'POST',
      url: '/api/v1/auth/register',
      payload: { email: 'not-an-email', password: 'password123' },
    });
    expect(res.statusCode).toBe(400);
  });

  it('returns 400 for short password', async () => {
    const res = await server.inject({
      method: 'POST',
      url: '/api/v1/auth/register',
      payload: { email: 'valid@example.com', password: 'short' },
    });
    expect(res.statusCode).toBe(400);
  });
});

describe('POST /api/v1/auth/login', () => {
  it('returns JWT for valid credentials', async () => {
    await server.inject({
      method: 'POST',
      url: '/api/v1/auth/register',
      payload: { email: 'login@example.com', password: 'password123' },
    });

    const res = await server.inject({
      method: 'POST',
      url: '/api/v1/auth/login',
      payload: { email: 'login@example.com', password: 'password123' },
    });

    expect(res.statusCode).toBe(200);
    expect(res.json().accessToken).toBeTruthy();
  });

  it('returns 401 for wrong password', async () => {
    await server.inject({
      method: 'POST',
      url: '/api/v1/auth/register',
      payload: { email: 'wrongpass@example.com', password: 'correctpassword' },
    });

    const res = await server.inject({
      method: 'POST',
      url: '/api/v1/auth/login',
      payload: { email: 'wrongpass@example.com', password: 'wrongpassword' },
    });

    expect(res.statusCode).toBe(401);
  });

  it('returns 401 for unregistered email', async () => {
    const res = await server.inject({
      method: 'POST',
      url: '/api/v1/auth/login',
      payload: { email: 'nobody@example.com', password: 'password123' },
    });
    expect(res.statusCode).toBe(401);
  });
});

describe('GET /api/v1/auth/me', () => {
  it('returns user profile with valid token', async () => {
    const reg = await server.inject({
      method: 'POST',
      url: '/api/v1/auth/register',
      payload: { email: 'me@example.com', password: 'password123' },
    });
    const { token } = reg.json();

    const res = await server.inject({
      method: 'GET',
      url: '/api/v1/auth/me',
      headers: { authorization: `Bearer ${token}` },
    });

    expect(res.statusCode).toBe(200);
    expect(res.json().user.email).toBe('me@example.com');
  });

  it('returns 401 without token', async () => {
    const res = await server.inject({ method: 'GET', url: '/api/v1/auth/me' });
    expect(res.statusCode).toBe(401);
  });
});
