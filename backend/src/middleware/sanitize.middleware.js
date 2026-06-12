import xss from "xss";
import logger from "../config/winston.logger.js";
import { BadRequestError } from "../errors/error.js";
import securityConfig from "../config/security.config.js";

const MAX_DEPTH = 5; // Limit recursion depth to prevent DoS
const MAX_STRING_LENGTH = 10000; // Limit string length to prevent abuse
const EXCLUDED_FIELDS = [
  "password",
  "confirmPassword",
  "currentPassword",
  "newPassword",
  "token",
  "refreshToken",
  "accessToken",
  "secret",
];

/**
 * Recursively sanitize a value against XSS attacks.
 * Handles strings, arrays, and plain objects.
 */
function sanitizeValue(value, depth = 0, key = "") {
  if (depth > MAX_DEPTH) {
    logger.warn(`XSS sanitizer: Payload too deep (depth=${depth}) for key=${key}`);
    throw new BadRequestError("Payload too deep: Potential DoS attack detected.");
  }
  if (typeof value === "string") {
    if (value.length > MAX_STRING_LENGTH) {
      logger.warn(`XSS sanitizer: String too long (length=${value.length}) for key=${key}`);
      throw new BadRequestError("String too long: Potential DoS attack detected.");
    }
    if (EXCLUDED_FIELDS.includes(key)) return value;
    return xss(value);
  }
  if (Array.isArray(value)) {
    return value.map((item, idx) => sanitizeValue(item, depth + 1, `${key}[${idx}]`));
  }
  if (value !== null && typeof value === "object") {
    const result = {};
    for (const [k, v] of Object.entries(value)) {
      result[k] = sanitizeValue(v, depth + 1, k);
    }
    return result;
  }
  return value;
}

export const sanitizeAll = () => {
  return (req, res, next) => {
    try {
      if (req.body) req.body = sanitizeValue(req.body);
      if (req.query) req.query = sanitizeValue(req.query);
      if (req.params) req.params = sanitizeValue(req.params);
      next();
    } catch (error) {
      next(error);
    }
  };
};

export const sanitizeFields = (policies) => {
  return (req, res, next) => {
    try {
      if (req.body) {
        for (const [field, policyName] of Object.entries(policies)) {
          if (req.body[field] !== undefined && typeof req.body[field] === "string") {
            if (EXCLUDED_FIELDS.includes(field)) continue;
            req.body[field] = sanitizeValue(req.body[field]);
          }
        }
      }
      next();
    } catch (error) {
      next(error);
    }
  };
};

export const detectSuspiciousPayload = () => {
  return (req, res, next) => {
    const rawBodySize = JSON.stringify(req.body || {}).length;
    const rawQuerySize = JSON.stringify(req.query || {}).length;
    if (rawBodySize > 50000 || rawQuerySize > 5000) {
      logger.warn(`Large payload detected: body=${rawBodySize} query=${rawQuerySize}`, {
        path: req.originalUrl,
        ip: req.ip,
        userAgent: req.headers["user-agent"],
      });
    }
    next();
  };
};
