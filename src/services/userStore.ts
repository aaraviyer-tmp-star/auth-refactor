import { User } from '../types/auth';

/**
 * In-memory user store.
 * In production, replace with your DB adapter (Prisma, TypeORM, pg, etc.)
 * The interface is intentionally narrow so swapping is a one-file change.
 */
class UserStore {
  private users: Map<string, User> = new Map();
  private emailIndex: Map<string, string> = new Map();  // email → userId
  private refreshTokens: Map<string, { userId: string; expiresAt: number }> = new Map();

  /** Reset all in-memory state — use only in tests */
  clear(): void {
    this.users.clear();
    this.emailIndex.clear();
    this.refreshTokens.clear();
  }

  async findById(id: string): Promise<User | null> {
    return this.users.get(id) ?? null;
  }

  async findByEmail(email: string): Promise<User | null> {
    const id = this.emailIndex.get(email.toLowerCase());
    if (!id) return null;
    return this.users.get(id) ?? null;
  }

  async create(user: User): Promise<User> {
    this.users.set(user.id, user);
    this.emailIndex.set(user.email.toLowerCase(), user.id);
    return user;
  }

  // ── Refresh token registry ─────────────────────────────────────────────────

  addRefreshToken(tokenId: string, userId: string, expiresAtSec: number): void {
    this.refreshTokens.set(tokenId, { userId, expiresAt: expiresAtSec });
  }

  consumeRefreshToken(tokenId: string): { userId: string } | null {
    const entry = this.refreshTokens.get(tokenId);
    if (!entry) return null;
    if (entry.expiresAt < Math.floor(Date.now() / 1000)) {
      this.refreshTokens.delete(tokenId);
      return null;
    }
    this.refreshTokens.delete(tokenId);   // rotate: consume old token
    return { userId: entry.userId };
  }

  revokeAllUserTokens(userId: string): void {
    for (const [id, entry] of this.refreshTokens) {
      if (entry.userId === userId) this.refreshTokens.delete(id);
    }
  }
}

export const userStore = new UserStore();
