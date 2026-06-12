import passport from "passport";
import logger, { logSecurityEvent } from "../config/winston.logger.js";
import { UnauthorizedError } from "../errors/error.js";

const requireAuth = (req, res, next) => {
  if (process.env.NODE_ENV !== "production") {
    logger.debug("Request cookies in requireAuth", { cookies: req.cookies });
  }

  passport.authenticate("jwt", { session: false }, (error, user, info) => {
    if (process.env.NODE_ENV !== "production") {
      logger.debug("Passport result - err:", error, "user:", user, "info:", info);
    }

    if (error) {
      logger.error("Error during authentication", {
        error: error.message,
        stack: error.stack,
        path: req.originalUrl,
        ip: req.ip,
      });
      return next(error);
    }
    if (!user) {
      logSecurityEvent("JWT_AUTH_FAILED", null, req.ip, req.headers["user-agent"], {
        path: req.originalUrl,
        method: req.method,
        reason: info?.message || "Authentication failed",
      });
      logger.warn("JWT authentication failed", {
        error: info?.message || "Authentication failed",
        path: req.originalUrl,
        ip: req.ip,
      });

      return next(new UnauthorizedError("Invalid or expired token"));
    }

    if (process.env.NODE_ENV !== "production") {
      logger.debug("User authenticated successfully in requireAuth", {
        userId: user._id,
        email: user.email,
      });
    }

    logger.info("User authenticated successfully via JWT", {
      userId: user._id,
      email: user.email,
      path: req.originalUrl,
    });
    req.user = user;
    next();
  })(req, res, next);
};

export default requireAuth;
