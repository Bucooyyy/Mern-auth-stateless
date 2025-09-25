import { Router } from "express";
import passport from "passport";
import jwt from "jsonwebtoken";
import { register, login, authStatus, logout, rotateTokens } from "../controllers/authController.js";
import { enableMFA, verifyMFA, resetMFA, disableMFA } from "../controllers/mfaController.js";

import { sanitizeMiddleware, fieldSanitizeMiddleware } from "../middleware/sanitize.js";
import requireAuth from "../middleware/requireAuth.js";

import { blackListToken } from "../utils/tokenjwt.js";

import { validateLogin, validateRegistration } from "../validators/auth.validator.js";
import { validationHandler } from "../middleware/handler/validationHandler.js";

const router = Router();

router.use(sanitizeMiddleware());

// Registration Route
router.post(
  "/register",
  //   fieldSanitizeMiddleware({
  //     username: "USERNAME",
  //     email: "EMAIL",
  //     password: "PASSWORD",
  //   }),
  //   validateRegistration,
  //   validationHandler,
  register
);
// Login Route
router.post(
  "/login",
  //   fieldSanitizeMiddleware({
  //     email: "EMAIL",
  //     password: "PASSWORD",
  //   }),
  //   validateLogin,
  //   validationHandler,
  login
);
// Logout Route
router.post("/logout", logout);
//  MFA setup
router.post("/mfa/enable", requireAuth, enableMFA);
// Verify Route
router.post("/mfa/verify", requireAuth, verifyMFA);
//  Reset MFA  Route
router.post("/mfa/reset", requireAuth, resetMFA);

router.post("/mfa/disable", requireAuth, disableMFA);

// Auth Status Route
router.get("/profil", requireAuth, authStatus);

// Tambahkan di routes untuk debugging
router.get("/debug-cookies", (req, res) => {
  console.log("=== DEBUG COOKIES ===");
  console.log("All cookies:", req.cookies);

  // Test access token
  if (req.cookies.accessToken) {
    try {
      const decoded = jwt.verify(req.cookies.accessToken, process.env.JWT_SECRET);
      console.log("Access token valid:", decoded);
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
router.post("/blacklist-token:", (req, res) => {
  console.log("=== ROute Blacklist ===");
  if (req.cookies.accessToken) {
    try {
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
