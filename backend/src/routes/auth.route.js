import { Router } from "express";
import jwt from "jsonwebtoken";
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
  oauthSuccess,
} from "../controllers/authController.js";

import { sanitizeMiddleware, fieldSanitizeMiddleware } from "../middleware/sanitize.js";
import requireAuth from "../middleware/requireAuth.js";

import { blacklistToken } from "../utils/tokenjwt.js";

import { authLimiter, sensitiveLimiter } from "../middleware/rateLimiter.js";

const router = Router();

router.use(sanitizeMiddleware());

// Registration Route
router.post("/register", register);
// Login Route
router.post("/login", authLimiter, login);
// Login MFA Verify Route
router.post("/verify-mfa", authLimiter, verifyMfaLogin);
// Logout Route
router.post("/logout", logout);

// Email Verification
router.post("/verify-email", sensitiveLimiter, confirmEmailVerification);

// Password Reset
router.post("/forgot-password", sensitiveLimiter, requestPasswordReset);
router.post("/reset-password", sensitiveLimiter, confirmPasswordReset);

// Auth Status Route
router.get("/profil", requireAuth, authStatus);

// Tambahkan di routes untuk debugging
router.get("/debug-cookies", (req, res) => {
  console.log("=== DEBUG COOKIES ===");
  console.log("All cookies:", req.cookies);

  // Test access token
  if (req.cookies.accessToken) {
    try {
      res.json({
        success: true,
        accessToken: decoded,
        cookieFound: true,
      });
    } catch (error) {
      console.log("Access token invalid:", error.message);
      res.json({
        success: false,
        error: error.message,
        cookieFound: true,
      });
    }
  } else {
    console.log("No access token cookie found");
    res.json({
      success: false,
      error: "No access token cookie",
      cookieFound: false,
      allCookies: req.cookies,
    });
  }
});

// Test BlackList
router.post("/blacklist-token", (req, res) => {
  console.log("=== ROute Blacklist ===");
  if (req.cookies.accessToken) {
    try {
      blacklistToken(req.cookies.accessToken);
      res.json({
        success: true,
        message: "Token blacklisted",
      });
    } catch (error) {
      console.log("No access token cookie found");
      res.json({
        success: false,
        error: "No access token cookie",
        cookieFound: false,
        allCookies: req.cookies,
      });
    }
  }
});

// rotate token route
router.post("/session/rotate", requireAuth, rotateTokens);

export default router;
