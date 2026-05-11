export interface User {
  id: string;
  email: string;
  passwordHash: string;
  createdAt: Date;
}

export interface TokenPayload {
  sub: string;   // user id
  email: string;
  iat: number;
  exp: number;
}

export interface RefreshTokenPayload extends TokenPayload {
  jti: string;   // unique token id — used for rotation/revocation
}

export interface AuthTokens {
  accessToken: string;
  refreshToken: string;
  accessExpiresIn: number;   // seconds
  refreshExpiresIn: number;   // seconds
}

export interface RegisterInput {
  email: string;
  password: string;
}

export interface LoginInput {
  email: string;
  password: string;
}

// Augment Express Request to include the authenticated user
declare global {
  namespace Express {
    interface Request {
      user?: {
        id: string;
        email: string;
      };
    }
  }
}
