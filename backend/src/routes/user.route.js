import { Router } from "express";
import { getProfile, updateProfile, updatePassword, deleteAccount } from "../controllers/userController.js";
import requireAuth from "../middleware/requireAuth.js";
import { validateProfileUpdate, checkValidation } from "../validators/auth.validator.js";
import { sensitiveLimiter } from "../middleware/rateLimiter.js";

const router = Router();

router.use(requireAuth);

router.get("/me", getProfile);
router.patch("/me", validateProfileUpdate, checkValidation, updateProfile);
router.patch("/me/password", sensitiveLimiter, updatePassword);
router.delete("/me", sensitiveLimiter, deleteAccount);

export default router;
