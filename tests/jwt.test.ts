import { generateTokens, verifyAccessToken, verifyRefreshToken, parseExpiry } from '../src/utils/jwt';

describe('JWT utilities', () => {
  const userId = 'user-123';
  const email = 'test@example.com';

  describe('parseExpiry', () => {
    it('parses seconds', () => {
      expect(parseExpiry('30s')).toBe(30);
    });

    it('parses minutes', () => {
      expect(parseExpiry('15m')).toBe(900);
    });

    it('parses hours', () => {
      expect(parseExpiry('1h')).toBe(3600);
    });

    it('parses days', () => {
      expect(parseExpiry('7d')).toBe(604800);
    });

    it('throws on invalid format', () => {
      expect(() => parseExpiry('abc')).toThrow('Invalid expiry format');
    });
  });

  describe('generateTokens', () => {
    it('returns access and refresh tokens', () => {
      const result = generateTokens(userId, email);
      expect(result.accessToken).toBeTruthy();
      expect(result.refreshToken).toBeTruthy();
      expect(result.accessExpiresIn).toBeGreaterThan(0);
      expect(result.refreshExpiresIn).toBeGreaterThan(result.accessExpiresIn);
    });

    it('sets correct subject (userId) in access token', () => {
      const { accessToken } = generateTokens(userId, email);
      const payload = verifyAccessToken(accessToken);
      expect(payload.sub).toBe(userId);
      expect(payload.email).toBe(email);
    });

    it('sets unique jti on refresh token', () => {
      const { refreshToken: t1 } = generateTokens(userId, email);
      const { refreshToken: t2 } = generateTokens(userId, email);
      const p1 = verifyRefreshToken(t1);
      const p2 = verifyRefreshToken(t2);
      expect(p1.jti).not.toBe(p2.jti);
    });
  });

  describe('verifyAccessToken', () => {
    it('accepts a valid token', () => {
      const { accessToken } = generateTokens(userId, email);
      const payload = verifyAccessToken(accessToken);
      expect(payload.sub).toBe(userId);
    });

    it('throws on tampered token', () => {
      expect(() => verifyAccessToken('tampered.token.here')).toThrow();
    });

    it('throws on expired token', () => {
      // Manually create an expired token by forging the payload
      const jwt = require('jsonwebtoken');
      const expired = jwt.sign(
        { sub: userId, email, exp: Math.floor(Date.now() / 1000) - 60 },
        process.env.JWT_SECRET!,
      );
      expect(() => verifyAccessToken(expired)).toThrow('jwt expired');
    });
  });

  describe('verifyRefreshToken', () => {
    it('accepts a valid refresh token', () => {
      const { refreshToken } = generateTokens(userId, email);
      const payload = verifyRefreshToken(refreshToken);
      expect(payload.sub).toBe(userId);
      expect(payload.jti).toBeTruthy();
    });

    it('throws on invalid token', () => {
      expect(() => verifyRefreshToken('bad.token.here')).toThrow();
    });
  });
});
