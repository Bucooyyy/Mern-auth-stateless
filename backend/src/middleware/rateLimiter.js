import rateLimit from "express-rate-limit";

const WINDOW_MS = Number(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000; // 15 min
const MAX = Number(process.env.RATE_LIMIT_MAX) || 300;

const limiterFactory = (windowMs, max, message) =>
  rateLimit({
    windowMs,
    max,
    standardHeaders: true, // Return rate limit info in `RateLimit-*` headers
    legacyHeaders: false,
    message: { success: false, message },
  });

// General limiter applied to all routes — PRD §9: 300 req/15min per IP
export const generalLimiter = limiterFactory(WINDOW_MS, MAX, "Too many requests, please try again later.");

// Login — PRD §9: 10 req/15min per IP (brute-force protection)
export const authLimiter = limiterFactory(15 * 60 * 1000, 10, "Too many authentication attempts, please try again in 15 minutes.");

// Register — PRD §9: 5 req/hour per IP (anti account-spam)
export const registerLimiter = limiterFactory(60 * 60 * 1000, 5, "Too many registration attempts, please try again in an hour.");

// verify-otp / MFA verify — PRD §9: 5 req/10min (anti brute-force of 6-digit OTP)
export const otpVerifyLimiter = limiterFactory(10 * 60 * 1000, 5, "Too many verification attempts, please try again in 10 minutes.");

// resend-otp — PRD §9: 1 req/min (anti email bombing)
export const resendOtpLimiter = limiterFactory(60 * 1000, 1, "Please wait before requesting another code.");

// forgot-password / reset-password — PRD §9: 3 req/15min (anti email bombing + enumeration probing)
export const sensitiveLimiter = limiterFactory(15 * 60 * 1000, 3, "Too many sensitive requests, please try again in 15 minutes.");

// refresh-token — PRD §9: 30 req/15min (used automatically by clients, kept loose)
export const refreshLimiter = limiterFactory(15 * 60 * 1000, 30, "Too many session refresh attempts, please try again later.");
