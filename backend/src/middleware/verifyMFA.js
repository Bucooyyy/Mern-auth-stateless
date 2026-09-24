import { ForbiddenError } from "../errors/error.js";
import jwt from "jsonwebtoken";
import logger from "../config/winston.logger.js";
/**
 * Middleware to check if the user has completed MFA if it is enabled for them.
 * This expects `req.user` to be populated (e.g. by `requireAuth.js`).
 * If MFA is enabled for the user, the access token must carry `mfaVerified: true`,
 * which is only set once the user has completed MFA verification.
 * @param {import('express').Request} req - Express request object.
 * @param {import('express').Response} res - Express response object.
 * @param {import('express').NextFunction} next - Express next middleware function.
 */
const verifyMFA = (req, res, next) => {
  try {
    const { user } = req;

    if (!user) {
      logger.warn("verifyMFA called without authenticated user", {
        path: req.originalUrl,
        ip: req.ip,
      });
      return next(new ForbiddenError("User not authenticated"));
    }

    // Check if MFA is enabled
    const mfaEnabled = user.MFA && user.MFA.enabled;

    if (!mfaEnabled) {
      logger.debug(`MFA not enabled for user ${user._id}, skipping verification`);
      return next(); // MFA not enabled, proceed
    }

    logger.debug(`MFA enabled for user ${user._id}, verifying session`, {
      userId: user._id,
      email: user.email,
    });

    const authHeader = req.headers.authorization;
    let token = null;
    if (authHeader && authHeader.startsWith("Bearer ")) {
      token = authHeader.split(" ")[1];
    } else if (req.cookies && req.cookies.accessToken) {
      token = req.cookies.accessToken;
    }

    if (!token) {
      logger.warn(`MFA required but no access token provided for user ${user._id}`, {
        path: req.originalUrl,
        ip: req.ip,
      });
      return next(new ForbiddenError("MFA verification required"));
    }

    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET);
    } catch (error) {
      logger.error(`Failed to decode token during MFA check for user ${user._id}`, { error: error.message, stack: error.stack });
      return next(new ForbiddenError("Invalid token format"));
    }

    // Access token is only issued with mfaVerified:true after the user passed
    // MFA (see authController.verifyMfaLogin / generateAccessToken(user, true)).
    if (!decoded || decoded.mfaVerified !== true) {
      return next(new ForbiddenError("MFA verification required"));
    }

    next();
  } catch (error) {
    next(new ForbiddenError("Invalid token or MFA state"));
  }
};

export default verifyMFA;
