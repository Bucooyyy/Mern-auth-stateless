import { AppError } from "../../errors/error.js";
import logger from "../../config/winston.logger.js";

/**
 * Central Express error handler.
 * Must be the LAST middleware registered in index.js (4-argument signature).
 *
 * Produces a consistent JSON shape:
 *   { success: false, message: string, errors?: any }
 */

const errorHandler = (err, req, res, _next) => {
  // ── Operational / expected errors (AppError subclasses) ──────────────────
  if (err instanceof AppError) {
    logger.warn(`[${err.statusCode}] ${err.message}`, {
      path: req.path,
      method: req.method,
      errors: err.errors,
    });

    return res.status(err.statusCode).json({
      success: false,
      message: err.message,
      ...(err.errors && { errors: err.errors }),
    });
  }

  // ── Mongoose validation errors ────────────────────────────────────────────
  if (err.name === "ValidationError") {
    const errors = Object.values(err.errors).map((e) => ({
      field: e.path,
      message: e.message,
    }));
    logger.warn("Mongoose validation error", { errors });
    return res.status(400).json({
      success: false,
      message: "Validation failed",
      errors,
    });
  }

  // ── Mongoose duplicate key ────────────────────────────────────────────────
  if (err.code === 11000) {
    const field = Object.keys(err.keyValue || {})[0] || "field";
    logger.warn("Duplicate key error", { field, value: err.keyValue });
    return res.status(409).json({
      success: false,
      message: `${field} already exists`,
    });
  }

  // ── JWT errors forwarded without middleware wrapping ──────────────────────
  if (err.name === "JsonWebTokenError" || err.name === "TokenExpiredError") {
    return res.status(401).json({ success: false, message: "Invalid or expired token" });
  }

  // ── Unexpected / programming errors ──────────────────────────────────────
  logger.error("Unhandled server error", {
    message: err.message,
    stack: process.env.NODE_ENV !== "production" ? err.stack : undefined,
    path: req.path,
    method: req.method,
  });

  return res.status(500).json({
    success: false,
    message: process.env.NODE_ENV === "production" ? "An internal server error occurred" : err.message,
  });
};

export default errorHandler;
