import xss from "xss";
import { BadRequestError } from "../errors/error.js";
/**
 * Recursively sanitize a value against XSS attacks.
 * Handles strings, arrays, and plain objects.
 */

const MAX_DEPTH = 5; // Limit recursion depth to prevent DoS
const MAX_STRING_LENGTH = 10000; // Limit string length to prevent abuse
const sanitize = (value, currentDepth = 0) => {
  if (currentDepth > MAX_DEPTH) {
    throw new BadRequestError("Payload too deep: Potential DoS attack detected.");
  }

  if (typeof value === "string") {
    if (value.length > MAX_STRING_LENGTH) {
      throw new BadRequestError("String too long: Potential DoS attack detected.");
    }
    return xss(value);
  }
  if (Array.isArray(value)) {
    return value.map((item) => sanitize(item, currentDepth + 1));
  }
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, sanitize(v, currentDepth + 1)]));
  }

  return value;
};

export const sanitizeInput = (value) => sanitize(value);

export const sanitizeObject = (obj) => {
  if (obj && typeof obj === "object" && !Array.isArray(obj)) {
    for (let key in obj) {
      if (Object.prototype.hasOwnProperty.call(obj, key)) {
        obj[key] = sanitize(obj[key]);
      }
    }
  }
};

/**
 * Express middleware: sanitize req.body, req.query, and req.params in-place.
 */
const xssSanitize = (req, _res, next) => {
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
