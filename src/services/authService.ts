import { v4 as uuidv4 } from 'uuid';
import { User, AuthTokens, RegisterInput, LoginInput } from '../types/auth';
import { hashPassword, verifyPassword } from '../utils/password';
import { generateTokens, verifyRefreshToken } from '../utils/jwt';
import { userStore } from './userStore';

export class AuthService {
  /**
   * Register a new user.
   * Throws on duplicate email.
   */
  async register(input: RegisterInput): Promise<{ tokens: AuthTokens; user: Omit<User, 'passwordHash'> }> {
    const existing = await userStore.findByEmail(input.email);
    if (existing) {
      const err: any = new Error('Email already registered');
      err.statusCode = 409;
      throw err;
    }

    const passwordHash = await hashPassword(input.password);
    const user: User = {
      id: uuidv4(),
      email: input.email.toLowerCase().trim(),
      passwordHash,
      createdAt: new Date(),
    };

    await userStore.create(user);

    const tokens = generateTokens(user.id, user.email);

    // Register the refresh token so it's valid for rotation
    const refreshDecoded = verifyRefreshToken(tokens.refreshToken);
    userStore.addRefreshToken(refreshDecoded.jti, user.id, refreshDecoded.exp);

    const { passwordHash: _pw, ...safeUser } = user;
    return { tokens, user: safeUser };
  }

  /**
   * Login an existing user.
   * Throws on bad credentials.
   */
  async login(input: LoginInput): Promise<{ tokens: AuthTokens; user: Omit<User, 'passwordHash'> }> {
    const user = await userStore.findByEmail(input.email);
    if (!user) {
      const err: any = new Error('Invalid credentials');
      err.statusCode = 401;
      throw err;
    }

    const valid = await verifyPassword(input.password, user.passwordHash);
    if (!valid) {
      const err: any = new Error('Invalid credentials');
      err.statusCode = 401;
      throw err;
    }

    const tokens = generateTokens(user.id, user.email);

    const refreshDecoded = verifyRefreshToken(tokens.refreshToken);
    userStore.addRefreshToken(refreshDecoded.jti, user.id, refreshDecoded.exp);

    const { passwordHash: _pw, ...safeUser } = user;
    return { tokens, user: safeUser };
  }

  /**
   * Refresh tokens using a valid refresh token.
   * Implements rotation: the used refresh token is invalidated after use.
   */
  async refreshTokens(
    refreshToken: string,
  ): Promise<{ tokens: AuthTokens }> {
    let decoded;
    try {
      decoded = verifyRefreshToken(refreshToken);
    } catch (_err: any) {
      const e: any = new Error('Invalid or expired refresh token');
      e.statusCode = 401;
      throw e;
    }

    // Rotate: consume (invalidate) the old token
    const session = userStore.consumeRefreshToken(decoded.jti);
    if (!session) {
      const e: any = new Error('Refresh token reused or revoked');
      e.statusCode = 401;
      throw e;
    }

    const user = await userStore.findById(session.userId);
    if (!user) {
      const e: any = new Error('User not found');
      e.statusCode = 401;
      throw e;
    }

    const newTokens = generateTokens(user.id, user.email);
    const newDecoded = verifyRefreshToken(newTokens.refreshToken);
    userStore.addRefreshToken(newDecoded.jti, user.id, newDecoded.exp);

    return { tokens: newTokens };
  }

  /**
   * Logout: revoke all refresh tokens for a user.
   */
  async logout(userId: string): Promise<void> {
    userStore.revokeAllUserTokens(userId);
  }
}

export const authService = new AuthService();
