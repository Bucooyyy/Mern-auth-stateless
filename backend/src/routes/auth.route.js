import { Router } from "express";
import passport from "passport";

import { register, login, authStatus, logout, setupMFA, verifyMFA, resetMFA } from "../controllers/authController.js";

const router = Router();

// Registration Route
router.post("/register", register);
// Login Route
router.post("/login", login);
// Auth Status Route
router.get("/profil", passport.authenticate("jwt", { session: false }), authStatus);
// Logout Route
router.post("/logout", logout);
//  MFA setup
router.post("/mfa/setup", setupMFA);
// Verify Route
router.post("/mfa/verify", verifyMFA);
//  Reset MFA  Route
router.post("/mfa/reset", resetMFA);

export default router;
