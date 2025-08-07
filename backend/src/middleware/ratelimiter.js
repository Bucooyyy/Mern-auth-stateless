import rateLimit from "express-rate-limit";

export const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: "Too many authentication requests. Please wait before trying again.",
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.ip + (req.body.email || ""),
});

export const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // Limit each IP to 10 requests per windowMs
  message: "Too many login attempts, please try again later.",
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.ip + (req.body.email || ""),
});

export const MFAlimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 6 minutes
  max: 5,
  message: "Too many 2FA attempts, please try again later.",
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.ip + (req.body.email || ""),
});
