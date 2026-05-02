import rateLimit from "express-rate-limit";

const WINDOW_MS = Number(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000; // 15 min
const MAX = Number(process.env.RATE_LIMIT_MAX) || 100;

const limiterFactory = (windowMs, max, message) =>
  rateLimit({
    windowMs,
    max,
    standardHeaders: true, // Return rate limit info in `RateLimit-*` headers
    legacyHeaders: false,
    message: { success: false, message },
  });

// General limiter applied to all routes
export const generalLimiter = limiterFactory(WINDOW_MS, MAX, "Too many requests, please try again later.");

// Stricter limiter for sensitive auth endpoints
export const authLimiter = limiterFactory(
  15 * 60 * 1000, // 15 min window
  20,
  "Too many authentication attempts, please try again in 15 minutes.",
);

// Tightest limit for password reset / MFA
export const sensitiveLimiter = limiterFactory(
  60 * 60 * 1000, // 1 hour window
  10,
  "Too many sensitive requests, please try again in 1 hour.",
);
