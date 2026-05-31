import jwt from "jsonwebtoken";
import { getRedisClient } from "../config/redis.config.js";
import logger from "../config/winston.logger.js";

const redis = () => getRedisClient(); // lazy accessor

// ─── Access Token ─────────────────────────────────────────────────────────────
/**
 * Generate a short-lived access token.
 * Payload: { userId, role }
 */
export const generateAccessToken = (user) =>
  jwt.sign({ userId: user._id.toString(), role: user.role }, process.env.JWT_ACCESS_SECRET, {
    expiresIn: process.env.JWT_ACCESS_EXPIRES_IN || "15m",
  });

// ─── Refresh Token ────────────────────────────────────────────────────────────
/**
 * Generate a long-lived refresh token.
 * Payload: { userId }
 */
export const generateRefreshToken = (user) =>
  jwt.sign({ userId: user._id.toString() }, process.env.JWT_REFRESH_SECRET, { expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || "7d" });

// ─── MFA Temporary Token ──────────────────────────────────────────────────────
/**
 * Short-lived token (5 min) issued when login requires MFA.
 * The client must pass this to POST /mfa/verify.
 */
export const generateMfaToken = (user) =>
  jwt.sign({ userId: user._id.toString(), purpose: "mfa_verification" }, process.env.JWT_MFA_SECRET, {
    expiresIn: process.env.JWT_MFA_EXPIRES_IN || "5m",
  });

export const verifyMfaToken = (token) => jwt.verify(token, process.env.JWT_MFA_SECRET);

// ─── Refresh Token Verification ───────────────────────────────────────────────
export const verifyRefreshToken = (token) => jwt.verify(token, process.env.JWT_REFRESH_SECRET);

// ─── Redis Blacklist ──────────────────────────────────────────────────────────
/**
 * Blacklist a token in Redis until its natural expiry.
 * Key pattern: blacklist:<token>
 */
export const blacklistToken = async (token, exp) => {
  try {
    const now = Math.floor(Date.now() / 1000);
    const ttl = exp - now;
    if (ttl > 0) {
      await redis().set(`blacklist:${token}`, "1", "EX", ttl);
      logger.debug("Token blacklisted", { ttl });
    }
  } catch (err) {
    logger.error("Failed to blacklist token", { error: err.message });
  }
};

/**
 * Check whether a token has been blacklisted.
 */
export const isTokenBlacklisted = async (token) => {
  try {
    const val = await redis().get(`blacklist:${token}`);
    return val !== null;
  } catch (err) {
    logger.error("Failed to check blacklist", { error: err.message });
    return false; // fail open — token check happens upstream anyway
  }
};

// ─── Cookie helper ────────────────────────────────────────────────────────────
/** Milliseconds represented by the refresh expiry env var (default 7d). */
const REFRESH_MS = (() => {
  const raw = process.env.JWT_REFRESH_EXPIRES_IN || "7d";
  const match = raw.match(/^(\d+)([smhd])$/);
  if (!match) return 7 * 24 * 60 * 60 * 1000;
  const [, n, unit] = match;
  const multipliers = { s: 1e3, m: 60e3, h: 3600e3, d: 86400e3 };
  return Number(n) * multipliers[unit];
})();

/**
 * Set the refresh token as a secure HTTP-only cookie on the response.
 */
export const setRefreshTokenCookie = (res, refreshToken) => {
  res.cookie("refreshToken", refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: process.env.NODE_ENV === "production" ? "strict" : "lax",
    maxAge: REFRESH_MS,
    path: "/",
  });
};

/**
 * Clear the refresh token cookie.
 */
export const clearRefreshTokenCookie = (res) => {
  res.clearCookie("refreshToken", { path: "/" });
};
