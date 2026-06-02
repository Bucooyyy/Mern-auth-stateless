import { Router } from "express";
import { mfaSetup, enableMFA, verifyMFA, disableMFA, resetMFA } from "../controllers/mfaController.js";
import requireAuth from "../middleware/requireAuth.js";
import { sensitiveLimiter } from "../middleware/rateLimiter.js";
import { validateMfaToken, validateMfaVerify, checkValidation } from "../validators/auth.validator.js";

const router = Router();

//  MFA setup
router.post("/mfa/setup", requireAuth, mfaSetup);
// Enable MFA
router.post("/mfa/enable", sensitiveLimiter, requireAuth, validateMfaToken, checkValidation, enableMFA);
// Verify Route
router.post("/mfa/verify", sensitiveLimiter, requireAuth, validateMfaVerify, checkValidation, verifyMFA);
//  Reset MFA  Route
router.post("/mfa/disable", sensitiveLimiter, requireAuth, validateMfaToken, checkValidation, disableMFA);

router.post("/mfa/reset", sensitiveLimiter, requireAuth, resetMFA);
