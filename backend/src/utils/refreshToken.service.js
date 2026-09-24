import crypto from "crypto";
import User from "../models/user.model.js";
import logger from "../config/winston.logger.js";

// ─── Token utilities ──────────────────────────────────────────────────────────
/** Generate a cryptographically random hex token and its SHA-256 hash. */
export const createSecureToken = () => {
  const token = crypto.randomBytes(32).toString("hex");
  const hash = crypto.createHash("sha256").update(token).digest("hex");
  return { token, hash };
};

// ─── Refresh token management ─────────────────────────────────────────────────
const MAX_DEVICES = 5;

/**
 * Persist a refresh token to the user's refreshTokens array.
 * Evicts oldest entries if the device limit is exceeded.
 */
export const addRefreshToken = async (userId, token) => {
  const user = await User.findById(userId).select("+refreshTokens");
  if (!user) return;

  user.refreshTokens = [token, ...user.refreshTokens].slice(0, MAX_DEVICES);
  await user.save();
};

/**
 * Remove a specific refresh token from the user's refreshTokens array.
 */
export const removeRefreshToken = async (userId, token) => {
  await User.findByIdAndUpdate(userId, {
    $pull: { refreshTokens: token },
  });
};

/**
 * Remove ALL refresh tokens from a user (e.g., after password reset).
 */
export const removeAllRefreshTokens = async (userId) => {
  await User.findByIdAndUpdate(userId, { refreshTokens: [] });
  logger.info("All refresh tokens cleared for user", { userId });
};

/**
 * Check whether a refresh token is still in the user's array.
 * Provides a secondary validation layer beyond Redis.
 */
export const isRefreshTokenValid = async (userId, token) => {
  const user = await User.findById(userId).select("+refreshTokens");
  return user?.refreshTokens?.includes(token) ?? false;
};
