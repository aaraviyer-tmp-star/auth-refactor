import { Request, Response } from 'express';
import { authenticateToken } from '../src/middleware/authMiddleware';
import { generateTokens } from '../src/utils/jwt';

const mockResponse = () => {
  const res = {} as Response;
  res.status = jest.fn().mockReturnValue(res);
  res.json = jest.fn().mockReturnValue(res);
  return res;
};

describe('authenticateToken middleware', () => {
  it('returns 401 when no Authorization header is present', () => {
    const req = { headers: {} } as Request;
    const res = mockResponse();
    const next = jest.fn();

    authenticateToken(req, res, next);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({ error: expect.stringContaining('Missing') }),
    );
    expect(next).not.toHaveBeenCalled();
  });

  it('returns 401 when Authorization header does not start with Bearer', () => {
    const req = { headers: { authorization: 'Basic abc' } } as Request;
    const res = mockResponse();
    const next = jest.fn();

    authenticateToken(req, res, next);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(next).not.toHaveBeenCalled();
  });

  it('returns 401 for an invalid token', () => {
    const req = { headers: { authorization: 'Bearer invalid.token.here' } } as Request;
    const res = mockResponse();
    const next = jest.fn();

    authenticateToken(req, res, next);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({ error: 'Invalid access token' }),
    );
    expect(next).not.toHaveBeenCalled();
  });

  it('calls next() and attaches user for a valid token', () => {
    const userId = 'user-abc';
    const email = 'test@example.com';
    const { accessToken } = generateTokens(userId, email);

    const req = { headers: { authorization: `Bearer ${accessToken}` } } as unknown as Request;
    const res = mockResponse();
    const next = jest.fn();

    authenticateToken(req, res, next);

    expect(next).toHaveBeenCalled();
    expect((req as any).user).toEqual({ id: userId, email });
  });
});
