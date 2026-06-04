import xss from "xss";
import logger from "../config/winston.logger.js";
import { BadRequestError } from "../errors/error.js";

/**
 * Recursively sanitize a value against XSS attacks.
 * Handles strings, arrays, and plain objects.
 */

const MAX_DEPTH = 5; // Limit recursion depth to prevent DoS
const MAX_STRING_LENGTH = 10000; // Limit string length to prevent abuse
const EXCLUDED_FIELDS = ["password", "confirmPassword", "currentPassword", "newPassword", "token"];

function sanitize(value, depth = 0, key = "") {
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
    return value.map((item, idx) => sanitize(item, depth + 1, `${key}[${idx}]`));
  }
  if (value !== null && typeof value === "object") {
    const result = {};
    for (const [k, v] of Object.entries(value)) {
      result[k] = sanitize(v, depth + 1, k);
    }
    return result;
  }
  return value;
}

const xssSanitize = (req, res, next) => {
  try {
    if (req.body) req.body = sanitize(req.body);
    if (req.query) req.query = sanitize(req.query);
    if (req.params) req.params = sanitize(req.params);
    next();
  } catch (error) {
    next(error);
  }
};

export default xssSanitize;
