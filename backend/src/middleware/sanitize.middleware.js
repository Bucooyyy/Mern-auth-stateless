import { sanitize } from "../utils/sanitizer.js";
import logger from "../config/winston.logger.js";
import { BadRequestError } from "../errors/error.js";
import securityConfig from "../config/security.config.js";

export const sanitizeAll = () => {
  return (req, res, next) => {
    try {
      if (req.body) req.body = sanitize(req.body);
      if (req.query) req.query = sanitize(req.query);
      if (req.params) req.params = sanitize(req.params);
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
            // Jangan sanitasi field yang ada di EXCLUDED_FIELDS
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

            if (EXCLUDED_FIELDS.includes(field)) continue;

            // Gunakan sanitize biasa (bisa dikembangkan dengan custom XSS options sesuai policy)
            req.body[field] = sanitize(req.body[field]);
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
