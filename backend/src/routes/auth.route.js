import { Router } from "express";
import passport from "passport";

import { register, login, authStatus, logout, setup2FA, verify2FA, reset2FA } from "../controllers/authController.js";

const router = Router();

// Registration Route
router.post("/register", register);
// Login Route
router.post("/login", login);
// Auth Status Route
router.get("/profil", passport.authenticate("jwt", { session: false }), authStatus);
// Logout Route
router.post("/logout", logout);
//  2FA setup
router.post("/2fa/setup", setup2FA);
// Verify Route
router.post("verify", verify2FA);
//  Reset ROute
router.post("/2fa/reset", reset2FA);

export default router;
