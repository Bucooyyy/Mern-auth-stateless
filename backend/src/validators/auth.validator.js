import { body, param } from "express-validator";
import { validationResult } from "express-validator";
import { BadRequestError } from "../errors/error.js";

// ─── Error-checking middleware ────────────────────────────────────────────────
/**
 * Run after validation chains. Collects errors and throws a BadRequestError
 * so the central error handler produces a consistent response.
 */
export const checkValidation = (req, _res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    throw new BadRequestError("Validation failed", errors.array());
  }
  next();
};

// ─── Validation chains ────────────────────────────────────────────────────────
export const validateRegister = [
  body("name").trim().notEmpty().withMessage("Name is required").isLength({ min: 2, max: 50 }).withMessage("Name must be 2–50 characters"),

  body("email").trim().notEmpty().withMessage("Email is required").isEmail().withMessage("Invalid email format").normalizeEmail(),

  body("password")
    .notEmpty()
    .withMessage("Password is required")
    .isLength({ min: 8 })
    .withMessage("Password must be at least 8 characters")
    .matches(/[A-Z]/)
    .withMessage("Password must contain an uppercase letter")
    .matches(/[0-9]/)
    .withMessage("Password must contain a number")
    .matches(/[^A-Za-z0-9]/)
    .withMessage("Password must contain a special character"),
];

export const validateLogin = [
  body("email").trim().notEmpty().withMessage("Email is required").isEmail().withMessage("Invalid email format").normalizeEmail(),

  body("password").notEmpty().withMessage("Password is required"),
];

export const validateForgotPassword = [
  body("email").trim().notEmpty().withMessage("Email is required").isEmail().withMessage("Invalid email format").normalizeEmail(),
];

export const validateResetPassword = [
  body("token").trim().notEmpty().withMessage("Reset token is required"),

  body("password")
    .notEmpty()
    .withMessage("Password is required")
    .isLength({ min: 8 })
    .withMessage("Password must be at least 8 characters")
    .matches(/[A-Z]/)
    .withMessage("Password must contain an uppercase letter")
    .matches(/[0-9]/)
    .withMessage("Password must contain a number")
    .matches(/[^A-Za-z0-9]/)
    .withMessage("Password must contain a special character"),
];

export const validateMfaToken = [
  body("token")
    .trim()
    .notEmpty()
    .withMessage("TOTP token is required")
    .isLength({ min: 6, max: 6 })
    .withMessage("TOTP token must be exactly 6 digits")
    .isNumeric()
    .withMessage("TOTP token must be numeric"),
];

export const validateMfaVerify = [
  body("mfaToken").trim().notEmpty().withMessage("MFA session token is required"),

  body("token")
    .trim()
    .notEmpty()
    .withMessage("TOTP code is required")
    .isLength({ min: 6, max: 6 })
    .withMessage("TOTP code must be exactly 6 digits")
    .isNumeric()
    .withMessage("TOTP code must be numeric"),
];

export const validateRoleChange = [
  param("userId").isMongoId().withMessage("Invalid user ID"),

  body("role").notEmpty().withMessage("Role is required").isIn(["free", "premium", "admin"]).withMessage("Role must be free, premium, or admin"),
];

export const validateProfileUpdate = [
  body("name").optional().trim().isLength({ min: 2, max: 50 }).withMessage("Name must be 2–50 characters"),

  body("email").optional().trim().isEmail().withMessage("Invalid email format").normalizeEmail(),
];
