import { Router } from "express";
import {
  register,
  login,
  authStatus,
  logout,
  rotateTokens,
  verifyMfaLogin,
  confirmEmailVerification,
  requestPasswordReset,
  confirmPasswordReset,
} from "../controllers/authController.js";

import { detectSuspiciousPayload } from "../middleware/sanitize.middleware.js";
import requireAuth from "../middleware/requireAuth.js";

import { authLimiter, sensitiveLimiter, registerLimiter } from "../middleware/rateLimiter.js";
import { validateRegister, validateLogin, validateForgotPassword, validateResetPassword, checkValidation } from "../validators/auth.validator.js";

const router = Router();

router.use(detectSuspiciousPayload());

// Registration Route
router.post("/register", registerLimiter, validateRegister, checkValidation, register);
// Login Route
router.post("/login", authLimiter, validateLogin, checkValidation, login);
// Login MFA Verify Route
router.post("/verify-mfa", authLimiter, verifyMfaLogin);
// Logout Route
router.post("/logout", logout);

// Email Verification
router.post("/verify-email", sensitiveLimiter, confirmEmailVerification);

// Password Reset
router.post("/forgot-password", sensitiveLimiter, validateForgotPassword, checkValidation, requestPasswordReset);
router.post("/reset-password", sensitiveLimiter, validateResetPassword, checkValidation, confirmPasswordReset);

// Auth Status Route
router.get("/profil", requireAuth, authStatus);

// Refresh token: must NOT require a valid access token (that's the whole point
// of rotation — the access token may already be expired). Only the refresh
// token cookie is checked, inside the controller.
router.post("/session/rotate", rotateTokens);

export default router;
