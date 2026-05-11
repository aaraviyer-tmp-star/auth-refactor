import { Request, Response, NextFunction } from 'express';
import { validationResult, body } from 'express-validator';
import { authService } from '../services/authService';

// ── Validation middlewares ──────────────────────────────────────────────────

export const registerValidation = [
  body('email').isEmail().normalizeEmail().withMessage('Valid email is required'),
  body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters')
    .matches(/[A-Z]/)
    .withMessage('Password must contain at least one uppercase letter')
    .matches(/[a-z]/)
    .withMessage('Password must contain at least one lowercase letter')
    .matches(/\d/)
    .withMessage('Password must contain at least one digit'),
];

export const loginValidation = [
  body('email').isEmail().normalizeEmail().withMessage('Valid email is required'),
  body('password').notEmpty().withMessage('Password is required'),
];

// ── Helpers ─────────────────────────────────────────────────────────────────

const handleError = (res: Response, status: number, message: string, details?: unknown) => {
  const body: { error: string; details?: unknown } = { error: message };
  if (details) body.details = details;
  res.status(status).json(body);
};

// ── Controllers ─────────────────────────────────────────────────────────────

export const register = async (req: Request, res: Response, next: NextFunction) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return handleError(res, 400, 'Validation failed', errors.array());
  }

  try {
    const result = await authService.register(req.body);
    res.status(201).json({
      message: 'Registration successful',
      user: result.user,
      tokens: result.tokens,
    });
  } catch (err: any) {
    next(err);
  }
};

export const login = async (req: Request, res: Response, next: NextFunction) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return handleError(res, 400, 'Validation failed', errors.array());
  }

  try {
    const result = await authService.login(req.body);
    res.json({
      message: 'Login successful',
      user: result.user,
      tokens: result.tokens,
    });
  } catch (err: any) {
    next(err);
  }
};

export const refresh = async (req: Request, res: Response, next: NextFunction) => {
  const { refreshToken } = req.body;
  if (!refreshToken || typeof refreshToken !== 'string') {
    return handleError(res, 400, 'refreshToken is required');
  }

  try {
    const result = await authService.refreshTokens(refreshToken);
    res.json({ tokens: result.tokens });
  } catch (err: any) {
    next(err);
  }
};

export const logout = async (req: Request, res: Response, next: NextFunction) => {
  // req.user is set by authenticateToken middleware
  try {
    await authService.logout(req.user!.id);
    res.json({ message: 'Logged out successfully' });
  } catch (err: any) {
    next(err);
  }
};
