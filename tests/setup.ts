import dotenv from 'dotenv';
dotenv.config({ path: '.env.test' });

// Minimal test env — JWT_SECRET must be set
if (!process.env.JWT_SECRET) {
  process.env.JWT_SECRET = 'test-secret-minimum-32-characters-long';
}
if (!process.env.JWT_ACCESS_EXPIRY) {
  process.env.JWT_ACCESS_EXPIRY = '15m';
}
if (!process.env.JWT_REFRESH_EXPIRY) {
  process.env.JWT_REFRESH_EXPIRY = '7d';
}
