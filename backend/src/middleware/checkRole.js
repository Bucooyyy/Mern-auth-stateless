import logger, { logSecurityEvent } from "../config/winston.logger.js";
import { UnauthorizedError, ForbiddenError } from "../errors/error.js";

const checkRole = (...allowedRoles) => {
  return (req, res, next) => {
    try {
      if (!req.user) {
        logger.warn("Unauthorized access attempt without user.");
        logSecurityEvent("UNAUTHENTICATED_ACCESS", null, req.ip, req.headers["user-agent"], { pqth: req.originalUrl, method: req.method });
        return next(new UnauthorizedError("Authentication required."));
      }

      const userRoles = req.user.roles;
      const hasRole = Array.isArray(userRoles) ? userRoles.some((role) => allowedRoles.includes(role)) : allowedRoles.includes(userRoles);

      if (!hasRole) {
        logger.warn("Forbidden access attempt due to insufficient role.");
        logSecurityEvent("FORBIDDEN_ACCESS", req.user._id, req.ip, req.headers["user-agent"], {
          path: req.originalUrl,
          method: req.method,
          requiredRoles: allowedRoles,
          userRole: userRoles,
        });
        return next(new ForbiddenError("Insufficient role."));
      }

      next();
    } catch (error) {
      logger.error("Unexpected error occurred during role check:", { error: error.message });
      next(error);
    }
  };
};

export default checkRole;
