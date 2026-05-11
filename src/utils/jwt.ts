import jwt, { Algorithm } from 'jsonwebtoken';
import { config } from '../config';
import { AuthTokens, TokenPayload, RefreshTokenPayload } from '../types/auth';
import { v4 as uuidv4 } from 'uuid';

const ALGORITHM: Algorithm = 'HS256';

export const parseExpiry = (expiry: string): number => {
  const match = expiry.match(/^(\d+)([smhd])$/);
  if (!match) throw new Error(`Invalid expiry format: ${expiry}`);
  const value = parseInt(match[1], 10);
  const unit = match[2];
  const multipliers: Record<string, number> = { s: 1, m: 60, h: 3600, d: 86400 };
  return value * multipliers[unit];
};

export const generateTokens = (userId: string, email: string): AuthTokens => {
  const now = Math.floor(Date.now() / 1000);
  const accessExp = parseExpiry(config.jwt.accessExpiry);
  const refreshExp = parseExpiry(config.jwt.refreshExpiry);
  const jti = uuidv4();   // unique id for this refresh token instance

  const accessPayload: TokenPayload = {
    sub: userId,
    email,
    iat: now,
    exp: now + accessExp,
  };

  const refreshPayload: RefreshTokenPayload = {
    sub: userId,
    email,
    iat: now,
    exp: now + refreshExp,
    jti,
  };

  const accessToken = jwt.sign(accessPayload, config.jwt.secret, {
    algorithm: ALGORITHM,
  });

  const refreshToken = jwt.sign(refreshPayload, config.jwt.secret, {
    algorithm: ALGORITHM,
  });

  return {
    accessToken,
    refreshToken,
    accessExpiresIn: accessExp,
    refreshExpiresIn: refreshExp,
  };
};

export const verifyAccessToken = (token: string): TokenPayload => {
  return jwt.verify(token, config.jwt.secret, { algorithms: [ALGORITHM] }) as TokenPayload;
};

export const verifyRefreshToken = (token: string): RefreshTokenPayload => {
  return jwt.verify(token, config.jwt.secret, { algorithms: [ALGORITHM] }) as RefreshTokenPayload;
};

export const decodeToken = <T = TokenPayload>(token: string): T | null => {
  return jwt.decode(token) as T | null;
};
