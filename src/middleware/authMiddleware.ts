import { Request, Response, NextFunction } from 'express';
import { verifyAccessToken } from '../utils/jwt';

/**
 * Require a valid access token.
 * Attaches req.user on success.
 */
export const authenticateToken = (
  req: Request,
  res: Response,
  next: NextFunction,
): void => {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Missing or malformed Authorization header' });
    return;
  }

  const token = authHeader.slice(7);   // strip "Bearer "

  try {
    const payload = verifyAccessToken(token);
    req.user = { id: payload.sub, email: payload.email };
    next();
  } catch (err: any) {
    const message =
      err.name === 'TokenExpiredError'
        ? 'Access token expired'
        : 'Invalid access token';
    res.status(401).json({ error: message });
  }
};
