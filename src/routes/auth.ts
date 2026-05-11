import { Router } from 'express';
import {
  register,
  login,
  refresh,
  logout,
  registerValidation,
  loginValidation,
} from '../controllers/authController';
import { authenticateToken } from '../middleware/authMiddleware';

const router = Router();

// POST /auth/register
router.post('/register', registerValidation, register);

// POST /auth/login
router.post('/login', loginValidation, login);

// POST /auth/refresh
router.post('/refresh', refresh);

// POST /auth/logout  — protected
router.post('/logout', authenticateToken, logout);

export default router;
