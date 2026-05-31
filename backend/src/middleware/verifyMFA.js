import { AppError, ForbiddenError } from "../errors/error.js";
import jwt from "jsonwebtoken";

/**
 * Middleware to check if the user has completed MFA if it is enabled for them.
 * This expects `req.user` to be populated (e.g. by `requireAuth.js` or `checkToken.js`).
 * It checks if `req.user.MFA.enabled` or `req.user.isMFAEnabled` is true.
 * If true, it verifies if the access token has an `mfaVerified` flag, or if
 * another mechanism proves MFA was passed in this session.
 * For this implementation, we will check if the user has an active session and
 * maybe assume `accessToken` was issued after MFA, OR we can check for an MFA 
 * token if passed, depending on architecture. The prompt says: "Jika MFA enabled, 
 * pastikan sesi sudah melewati verifikasi MFA (misalnya, ada flag `mfaVerified` di JWT atau Redis)".
 * Let's assume the JWT access token payload should have `mfaVerified: true` if MFA is enabled.
 * @param {import('express').Request} req - Express request object.
 * @param {import('express').Response} res - Express response object.
 * @param {import('express').NextFunction} next - Express next middleware function.
 */
const verifyMFA = (req, res, next) => {
  try {
    const { user } = req;

    if (!user) {
      return next(new ForbiddenError("User not authenticated"));
    }

    // Check if MFA is enabled
    const mfaEnabled = (user.MFA && user.MFA.enabled) || user.isMFAEnabled;

    if (!mfaEnabled) {
      return next(); // MFA not enabled, proceed
    }

    // Since MFA is enabled, verify the session.
    // Let's decode the access token from req.headers.authorization to check mfaVerified.
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith("Bearer ")) {
      const token = authHeader.split(" ")[1];
      const decoded = jwt.decode(token);

      // If MFA is required but token doesn't say mfaVerified, deny.
      // Alternatively, the token itself is only issued after MFA (in authController.verifyMfaLogin).
      // So if they have an access token, it means they passed MFA.
      // But the prompt says: "Jika MFA enabled, pastikan sesi sudah melewati verifikasi MFA (misalnya, ada flag `mfaVerified` di JWT atau Redis)."
      // Let's check for `mfaVerified` flag in JWT. We should update generateToken to include it.
      if (!decoded || decoded.mfaVerified !== true) {
        return next(new ForbiddenError("MFA verification required"));
      }
    } else {
       return next(new ForbiddenError("MFA verification required"));
    }

    next();
  } catch (error) {
    next(new ForbiddenError("Invalid token or MFA state"));
  }
};

export default verifyMFA;
