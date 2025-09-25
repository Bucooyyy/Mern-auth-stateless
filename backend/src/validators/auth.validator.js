import { body, param, query } from "express-validator";
import user from "../models/user.model.js";

const passwordValidation = body("password")
  .isLength({ min: 8, max: 128 })
  .withMessage("Password must be between 8 and 128 characters long")
  .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
  .withMessage("Password must contain at least one lowercase letter, one uppercase letter, one number, and one special character (@$!%*?&)");

const emailValidation = body("email")
  .isEmail()
  .withMessage("Please provide a valid email address")
  .normalizeEmail()
  .isLength({ max: 254 })
  .withMessage("Email address is too long")
  .custom(async (value, { req }) => {
    const disposableDomains = ["10minutemail.com", "tempmail.org", "guerrillamail.com", "mailinator.com", "yopmail.com", "temp-mail.org"];
    const domain = value.split("@")[1];
    if (disposableDomains.includes(domain)) {
      throw new Error("Disposable email addresses are not allowed");
    }
    return true;
  });

const usernameValidation = body("username")
  .isLength({ min: 3, max: 50 })
  .withMessage("Username must be between 3 and 50 characters long")
  .matches(/^[a-zA-Z0-9_]+$/)
  .withMessage("Username can only contain letters, numbers, and underscores")
  .custom(async (value) => {
    const reservedUsernames = [
      "admin",
      "root",
      "administrator",
      "mod",
      "moderator",
      "support",
      "help",
      "api",
      "www",
      "mail",
      "ftp",
      "blog",
      "shop",
      "store",
      "test",
      "demo",
      "guest",
      "user",
      "null",
      "undefined",
      "system",
      "config",
      "settings",
    ];
    if (reservedUsernames.includes(value.toLowerCase())) {
      throw new Error("This username is reserved and cannot be used");
    }
    return true;
  });

export const validateRegistration = [
  body("username")
    .trim()
    .isLength({ min: 2, max: 50 })
    .withMessage("Username must between 2 and 50 characters long")
    .matches(/^[a-zA-Z\s\-']+$/)
    .withMessage("Username can only contain letters, spaces, hyphens, and apostrophes"),

  usernameValidation.custom(async (value) => {
    const existingUser = await user.findOne({ username: value });
    if (existingUser) {
      throw new Error("Username is already taken");
    }
    return true;
  }),

  emailValidation.custom(async (value) => {
    const existingUser = await user.findOne({ email: value });
    if (existingUser) {
      throw new Error("Email is already registered");
    }
    return true;
  }),

  passwordValidation,
  body("confirmPassword").custom((value, { req }) => {
    if (value !== req.body.password) {
      throw new Error("Password confirmation does not match password");
    }

    return true;
  }),

  ,
];

export const validateLogin = [
  body("identifier").notEmpty().withMessage("Email or username is required").trim().isLength({ max: 254 }).withMessage("Identifier is too long"),

  body("password").notEmpty().withMessage("Password is required").isLength({ min: 1, max: 128 }).withMessage("Password length is invalid"),

  // body("rememberMe").optional().isBoolean().withMessage("Remember me must be a boolean value"),
];

export const validatePasswordReset = [
  param("token")
    .isLength({ min: 64, max: 64 })
    .withMessage("Invalid reset token format")
    .matches(/^[a-f0-9]{64}$/)
    .withMessage("Reset token must be a valid hexadecimal string"),

  passwordValidation,

  body("confirmPassword").custom((value, { req }) => {
    if (value !== req.body.password) {
      throw new Error("Password confirmation does not match password");
    }
    return true;
  }),
];

export const validateProfileUpdate = [
  body("firstName")
    .optional()
    .trim()
    .isLength({ min: 2, max: 30 })
    .withMessage("First name must be between 2 and 50 characters long")
    .matches(/^[a-zA-Z\s\-']+$/)
    .withMessage("First name can only contain letters, spaces, hyphens, and apostrophes"),

  body("lastName")
    .optional()
    .trim()
    .isLength({ min: 2, max: 30 })
    .withMessage("Last name must be between 2 and 50 characters long")
    .matches(/^[a-zA-Z\s\-']+$/)
    .withMessage("Last name can only contain letters, spaces, hyphens, and apostrophes"),

  body("username")
    .optional()
    .isLength({ min: 3, max: 30 })
    .withMessage("Username must be between 3 and 30 characters long")
    .matches(/^[a-zA-Z0-9_]+$/)
    .withMessage("Username can only contain letters, numbers, and underscores")
    .custom(async (value, { req }) => {
      if (value && req.user.username !== value) {
        const existingUser = await User.findOne({ username: value });
        if (existingUser) {
          throw new Error("Username is already taken");
        }
      }
      return true;
    }),

  // body("email")
  //   .optional()
  //   .isEmail()
  //   .withMessage("Please provide a valid email address")
  //   .normalizeEmail()
  //   .custom(async (value, { req }) => {
  //     if (value && req.user.email !== value) {
  //       const existingUser = await User.findOne({ email: value });
  //       if (existingUser) {
  //         throw new Error("Email address is already registered");
  //       }
  //     }
  //     return true;
  //   }),
];

export const validateEmailVerification = [
  param("token")
    .isLength({ min: 64, max: 64 })
    .withMessage("Invalid verification token format")
    .matches(/^[a-f0-9]{64}$/)
    .withMessage("Verification token must be a valid hexadecimal string"),
];

// export const validateResendEmailVerification = [
//   emailValidation
// ];

export const validateRefreshToken = [
  body("refreshToken").notEmpty().withMessage("Refresh token is required").isJWT().withMessage("Invalid refresh token format"),
];

export const validateTwoFactorSetup = [
  body("secret").notEmpty().withMessage("Two-factor secret is required").isLength({ min: 32, max: 32 }).withMessage("Invalid secret format"),

  body("token")
    .notEmpty()
    .withMessage("Verification token is required")
    .isNumeric()
    .withMessage("Token must be numeric")
    .isLength({ min: 6, max: 6 })
    .withMessage("Token must be 6 digits"),
];

export const validateTwoFactorVerification = [
  body("token")
    .notEmpty()
    .withMessage("Two-factor token is required")
    .isNumeric()
    .withMessage("Token must be numeric")
    .isLength({ min: 6, max: 6 })
    .withMessage("Token must be 6 digits"),
];

export const validateAdminUserUpdate = [
  param("userId").isMongoId().withMessage("Invalid user ID"),

  body("role").optional().isIn(["user", "premium", "admin"]).withMessage("Invalid role"),

  body("isEmailVerified").optional().isBoolean().withMessage("Email verification status must be a boolean"),
];

export const validateUserSearch = [
  query("page").optional().isInt({ min: 1 }).withMessage("Page must be a positive integer"),

  query("limit").optional().isInt({ min: 1, max: 100 }).withMessage("Limit must be between 1 and 100"),

  query("search").optional().trim().isLength({ min: 1, max: 100 }).withMessage("Search term must be between 1 and 100 characters"),

  query("role").optional().isIn(["user", "premium", "admin"]).withMessage("Invalid role filter"),

  query("isEmailVerified").optional().isBoolean().withMessage("Email verification filter must be a boolean"),

  query("sortBy").optional().isIn(["createdAt", "updatedAt", "username", "email", "aiCredits"]).withMessage("Invalid sort field"),

  query("sortOrder").optional().isIn(["asc", "desc"]).withMessage("Sort order must be asc or desc"),
];
