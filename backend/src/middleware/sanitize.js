import { sanitizeInput, sanitizeObject } from "../utils/sanitizer.js";
import securityConfig from "../config/security.config.js";

export const sanitizeMiddleware = () => {
  return (req, res, next) => {
    try {
      if (req.body) {
        sanitizeObject(req.body, securityConfig.XSS_POLICIES.DEFAULT);
      }

      if (req.query) {
        sanitizeObject(req.query, {
          ...securityConfig.XSS_POLICIES.DEFAULT,
          context: "query",
        });
      }

      if (req.params) {
        sanitizeObject(req.params, {
          ...securityConfig.XSS_POLICIES.DEFAULT,
          context: "params",
        });
      }

      req.sanitized = {
        body: req.body,
        query: req.query,
        params: req.params,
      };

      next();
    } catch (error) {
      next(error);
    }
  };
};

export const fieldSanitizeMiddleware = (policies) => {
  return (req, res, next) => {
    try {
      if (req.body) {
        Object.keys(req.body).forEach((field) => {
          if (policies[field] && typeof req.body[field] === "string") {
            req.body[field] = sanitizeInput(req.body[field], securityConfig.XSS_POLICIES[policies[field]] || policies[field]);
          }
        });
      }
      next();
    } catch (error) {
      next(error);
    }
  };
};
