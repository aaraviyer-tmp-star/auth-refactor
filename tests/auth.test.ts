import request from 'supertest';
import app from '../src/app';
import { userStore } from '../src/services/userStore';

const api = () => request(app);

describe('Auth endpoints', () => {
  beforeAll(() => userStore.clear());
  afterEach(() => {
    jest.restoreAllMocks();
    userStore.clear();
  });

  // ── POST /auth/register ───────────────────────────────────────────────────

  describe('POST /auth/register', () => {
    const validUser = { email: 'alice@example.com', password: 'StrongPass1' };

    it('returns 201 and tokens on success', async () => {
      const res = await api()
        .post('/auth/register')
        .send(validUser)
        .expect(201);

      expect(res.body.message).toBe('Registration successful');
      expect(res.body.user.email).toBe(validUser.email);
      expect(res.body.tokens.accessToken).toBeTruthy();
      expect(res.body.tokens.refreshToken).toBeTruthy();
      expect(res.body.user).not.toHaveProperty('passwordHash');
    });

    it('returns 409 when email is already registered', async () => {
      await api().post('/auth/register').send(validUser);
      const res = await api()
        .post('/auth/register')
        .send(validUser)
        .expect(409);

      expect(res.body.error).toBe('Email already registered');
    });

    it('returns 400 for invalid email', async () => {
      const res = await api()
        .post('/auth/register')
        .send({ email: 'not-an-email', password: 'StrongPass1' })
        .expect(400);

      expect(res.body.error).toBe('Validation failed');
    });

    it('returns 400 when password is too short', async () => {
      const res = await api()
        .post('/auth/register')
        .send({ email: 'bob@example.com', password: 'short1A' })
        .expect(400);

      expect(res.body.error).toBe('Validation failed');
    });

    it('returns 400 when password lacks uppercase letter', async () => {
      const res = await api()
        .post('/auth/register')
        .send({ email: 'bob@example.com', password: 'weakpass1' })
        .expect(400);

      expect(res.body.error).toBe('Validation failed');
    });
  });

  // ── POST /auth/login ─────────────────────────────────────────────────────

  describe('POST /auth/login', () => {
    const credentials = { email: 'charlie@example.com', password: 'LoginPass1' };

    beforeEach(async () => {
      await api().post('/auth/register').send(credentials);
    });

    it('returns 200 and tokens on valid credentials', async () => {
      const res = await api()
        .post('/auth/login')
        .send(credentials)
        .expect(200);

      expect(res.body.message).toBe('Login successful');
      expect(res.body.tokens.accessToken).toBeTruthy();
      expect(res.body.tokens.refreshToken).toBeTruthy();
    });

    it('returns 401 for wrong password', async () => {
      const res = await api()
        .post('/auth/login')
        .send({ email: credentials.email, password: 'WrongPass1' })
        .expect(401);

      expect(res.body.error).toBe('Invalid credentials');
    });

    it('returns 401 for unknown email', async () => {
      const res = await api()
        .post('/auth/login')
        .send({ email: 'nobody@example.com', password: 'AnyPass1' })
        .expect(401);

      expect(res.body.error).toBe('Invalid credentials');
    });

    it('returns 400 when email is missing', async () => {
      const res = await api()
        .post('/auth/login')
        .send({ password: 'AnyPass1' })
        .expect(400);

      expect(res.body.error).toBe('Validation failed');
    });
  });

  // ── POST /auth/refresh ──────────────────────────────────────────────────

  describe('POST /auth/refresh', () => {
    const user = { email: 'diana@example.com', password: 'RefreshPass1' };
    let refreshToken: string;

    beforeEach(async () => {
      const res = await api().post('/auth/register').send(user);
      refreshToken = res.body.tokens.refreshToken;
    });

    it('returns new tokens on valid refresh token', async () => {
      const res = await api()
        .post('/auth/refresh')
        .send({ refreshToken })
        .expect(200);

      expect(res.body.tokens.accessToken).toBeTruthy();
      expect(res.body.tokens.refreshToken).not.toBe(refreshToken); // rotated
    });

    it('returns 401 when refresh token is missing', async () => {
      await api().post('/auth/refresh').send({}).expect(400);
    });

    it('returns 401 when refresh token is tampered', async () => {
      await api()
        .post('/auth/refresh')
        .send({ refreshToken: 'tampered.token' })
        .expect(401);
    });

    it('returns 401 when refresh token has been used (rotation enforcement)', async () => {
      // First use — should succeed
      await api().post('/auth/refresh').send({ refreshToken }).expect(200);

      // Reuse — should fail (token was rotated on first use)
      await api()
        .post('/auth/refresh')
        .send({ refreshToken })
        .expect(401);
    });
  });

  // ── POST /auth/logout ────────────────────────────────────────────────────

  describe('POST /auth/logout', () => {
    const user = { email: 'eve@example.com', password: 'LogoutPass1' };
    let accessToken: string;
    let refreshToken: string;

    beforeEach(async () => {
      const res = await api().post('/auth/register').send(user);
      accessToken = res.body.tokens.accessToken;
      refreshToken = res.body.tokens.refreshToken;
    });

    it('returns 200 on successful logout', async () => {
      await api()
        .post('/auth/logout')
        .set('Authorization', `Bearer ${accessToken}`)
        .expect(200);
    });

    it('returns 401 when not authenticated', async () => {
      await api().post('/auth/logout').expect(401);
    });

    it('returns 401 when token is invalid', async () => {
      await api()
        .post('/auth/logout')
        .set('Authorization', 'Bearer invalid.token')
        .expect(401);
    });
  });

  // ── Protected route ──────────────────────────────────────────────────────

  describe('GET /protected', () => {
    const user = { email: 'frank@example.com', password: 'ProtctPass1' };
    let accessToken: string;

    beforeEach(async () => {
      const res = await api().post('/auth/register').send(user);
      accessToken = res.body.tokens.accessToken;
    });

    it('returns user email for authenticated request', async () => {
      const res = await api()
        .get('/protected')
        .set('Authorization', `Bearer ${accessToken}`)
        .expect(200);

      expect(res.body.message).toContain(user.email);
    });

    it('returns 401 without token', async () => {
      await api().get('/protected').expect(401);
    });

    it('returns 401 when access token is expired', async () => {
      // Manually craft a token that expired 60 seconds ago
      const jwt = require('jsonwebtoken');
      const secret = process.env.JWT_SECRET!;
      const expiredToken = jwt.sign(
        { sub: 'any-user-id', email: 'any@email.com', exp: Math.floor(Date.now() / 1000) - 60 },
        secret,
      );

      await api()
        .get('/protected')
        .set('Authorization', `Bearer ${expiredToken}`)
        .expect(401)
        .expect({ error: 'Access token expired' });
    });

    it('returns 401 when access token is tampered', async () => {
      await api()
        .get('/protected')
        .set('Authorization', 'Bearer tampered.token.here')
        .expect(401)
        .expect({ error: 'Invalid access token' });
    });
  });

  // ── Health check ────────────────────────────────────────────────────────

  describe('GET /health', () => {
    it('returns 200 ok', async () => {
      await api().get('/health').expect(200, { status: 'ok' });
    });
  });
});
