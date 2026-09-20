import { Router } from "express";
import passport from "passport";
import { oauthSuccess } from "../controllers/authController";

const router = Router();

router.get("/google", passport.authenticate("google", { session: false, scope: ["profile", "email"] }));

router.get(
  "/google/callback",
  passport.authenticate("google", {
    session: false,
    failureRedirect: `${process.env.CLIENT_URL}/login?error=google_failed`,
  }),
  oauthSuccess,
);

// ─── Discord ──────────────────────────────────────────────────────────────────
router.get("/discord", passport.authenticate("discord", { session: false }));

router.get(
  "/discord/callback",
  passport.authenticate("discord", {
    session: false,
    failureRedirect: `${process.env.CLIENT_URL}/login?error=discord_failed`,
  }),
  oauthSuccess,
);

// ─── GitHub ───────────────────────────────────────────────────────────────────
router.get("/github", passport.authenticate("github", { session: false, scope: ["user:email"] }));

router.get(
  "/github/callback",
  passport.authenticate("github", {
    session: false,
    failureRedirect: `${process.env.CLIENT_URL}/login?error=github_failed`,
  }),
  oauthSuccess,
);

export default router;
