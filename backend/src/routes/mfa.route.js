import { Router } from "express";
import { setupMFA, enableMFA, verifyMFA, disableMFA, resetMFA } from "../controllers/mfaController.js";
import requireAuth from "../middleware/requireAuth.js";
import { sensitiveLimiter } from "../middleware/rateLimiter.js";
import { validateMfaToken, validateMfaVerify, checkValidation } from "../validators/auth.validator.js";

const router = Router();

//  MFA setup
router.post("/setup", requireAuth, setupMFA);
// Enable MFA
router.post("/enable", sensitiveLimiter, requireAuth, validateMfaToken, checkValidation, enableMFA);
// Verify Route (login-time step 2, uses tempToken — not requireAuth)
router.post("/verify", sensitiveLimiter, validateMfaVerify, checkValidation, verifyMFA);
//  Disable MFA Route
router.post("/disable", sensitiveLimiter, requireAuth, disableMFA);

router.post("/reset", sensitiveLimiter, requireAuth, resetMFA);

export default router;
