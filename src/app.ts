import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import authRoutes from './routes/auth';
import { authenticateToken } from './middleware/authMiddleware';

const app = express();

// ── Global middleware ───────────────────────────────────────────────────────
app.use(cors());
app.use(express.json());

// ── Routes ───────────────────────────────────────────────────────────────────
app.use('/auth', authRoutes);

// Example protected route — requires valid access token
app.get('/protected', authenticateToken, (req: Request, res: Response) => {
  res.json({ message: `Hello, ${req.user?.email}. You are authenticated.` });
});

// ── Health check ─────────────────────────────────────────────────────────────
app.get('/health', (_req: Request, res: Response) => {
  res.json({ status: 'ok' });
});

// ── 404 handler ──────────────────────────────────────────────────────────────
app.use((_req: Request, res: Response) => {
  res.status(404).json({ error: 'Not found' });
});

// ── Global error handler ─────────────────────────────────────────────────────
app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
  const status = err.statusCode ?? 500;
  const message = err.message ?? 'Internal server error';
  console.error(`[error] ${status} — ${message}`, err.stack);
  res.status(status).json({ error: message });
});

export default app;
