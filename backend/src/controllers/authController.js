import userModel from "../models/user.model.js";
import { hashPassword, comparePassword } from "../utils/crypto.js";
import {
  generateAccessToken,
  generateRefreshToken,
  generateMfaToken,
  verifyMfaToken,
  blacklistToken,
  isTokenBlacklisted,
  setRefreshTokenCookie,
  clearRefreshTokenCookie,
  verifyRefreshToken,
} from "../utils/tokenjwt.js";
import logger, { logSecurityEvent } from "../config/winston.logger.js";
import jwt from "jsonwebtoken";
import speakeasy from "speakeasy";
import crypto from "crypto";
import { sendEmailVerifyPasswordReset } from "../utils/mailsender.js";
import getTransporter from "../config/nodemailer.config.js";
import * as emailLogic from "../utils/mailsender.js";

import { AppError, BadRequestError, InternalServerError, UnauthorizedError } from "../errors/error.js";
import { sendSuccess } from "../utils/response.js";



/**
 * Register a new user.
 * @param {import('express').Request} req - Express request object.
 * @param {import('express').Response} res - Express response object.
 * @param {import('express').NextFunction} next - Express next middleware function.
 */
export const register = async (req, res, next) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return next(new BadRequestError("All fields are required"));
    }

    const existingUser = await userModel.findOne({ email });

    if (existingUser) {
      logSecurityEvent("REGISTRATION_BLOCKED", null, existingUser._id, req.ip, req.get("User-Agent"), { reason: "EMAIL_EXISTS", email });
      return next(new BadRequestError("User already exists"));
    }

    const hashedPassword = await hashPassword(password);

    const rawVerificationToken = crypto.randomBytes(32).toString("hex");
    const hashedVerificationToken = crypto.createHash("sha256").update(rawVerificationToken).digest("hex");

    const user = new userModel({
      name,
      email,
      password: hashedPassword,
      isAccountVerified: false,
      emailVerificationToken: hashedVerificationToken,
      emailVerificationTokenExpires: Date.now() + 10 * 60 * 1000, // 10 minutes
      isMFAEnabled: false,
      roles: "free",
    });

    await user.save();
    logger.info("User registered successfully:", { userId: user._id });

    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);
    setRefreshTokenCookie(res, refreshToken);

    user.refreshTokens.push(refreshToken);
    await user.save();

    await emailLogic.sendVerificationEmail(user.email, rawVerificationToken);

    logSecurityEvent("REGISTRATION_SUCCESS", user._id, req.ip, req.get("User-Agent"));

    return sendSuccess(res, 201, "User registered successfully", {
      accessToken,
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        role: user.roles,
        createdAt: user.createdAt,
      },
    });
  } catch (error) {
    logSecurityEvent("REGISTRATION_ERROR", null, req.ip, req.get("User-Agent"), {
      error: error.message,
    });
    next(error);
  }
};

/**
 * Login a user.
 * @param {import('express').Request} req - Express request object.
 * @param {import('express').Response} res - Express response object.
 * @param {import('express').NextFunction} next - Express next middleware function.
 */
export const login = async (req, res, next) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return next(new BadRequestError("All fields must be fulfilled"));
  }

  try {
    const user = await userModel
      .findOne({ email })
      .select("+password +MFA.enabled +MFA.secret +failedLoginAttempts +lockUntil +refreshTokens +roles");

    if (!user) {
      logSecurityEvent("LOGIN_FAILED", null, req.ip, req.get("User-Agent"), {
        reason: "USER_NOT_FOUND",
        email: email,
      });
      return next(new UnauthorizedError("Invalid credentials"));
    }

    if (user.lockUntil && user.lockUntil > Date.now()) {
      const remainingTime = Math.ceil((user.lockUntil - Date.now()) / 1000 / 60);
      return next(new UnauthorizedError(`Account locked. Try again in ${remainingTime} minutes.`));
    }

    const isPasswordValid = await comparePassword(password, user.password);

    if (!isPasswordValid) {
      user.failedLoginAttempts += 1;
      if (user.failedLoginAttempts >= 5) {
        user.lockUntil = Date.now() + 15 * 60 * 1000;
      }
      await user.save();
      return next(new UnauthorizedError("Invalid credentials"));
    }

    user.failedLoginAttempts = 0;
    user.lockUntil = null;
    await user.save();

    if (user.MFA && user.MFA.enabled) {
      const tempToken = generateMfaToken(user);
      return sendSuccess(res, 200, "MFA code required", {
        requiresMfa: true,
        tempToken,
      });
    }

    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);
    setRefreshTokenCookie(res, refreshToken);

    user.refreshTokens.push(refreshToken);
    await user.save();

    return sendSuccess(res, 200, "Logged in successfully", {
      accessToken,
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        role: user.roles,
      },
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Verify MFA token to complete login.
 * @param {import('express').Request} req - Express request object.
 * @param {import('express').Response} res - Express response object.
 * @param {import('express').NextFunction} next - Express next middleware function.
 */
export const verifyMfaLogin = async (req, res, next) => {
  const { otp } = req.body;
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return next(new UnauthorizedError("Missing temporary token"));
  }

  const tempToken = authHeader.split(" ")[1];

  try {
    const decoded = verifyMfaToken(tempToken);

    if (decoded.purpose !== "mfa_verification") {
      return next(new BadRequestError("Invalid token type"));
    }

    const user = await userModel.findById(decoded.userId).select("+MFA.secret +MFA.enabled +refreshTokens +roles");

    if (!user || !user.MFA || !user.MFA.enabled) {
      return next(new BadRequestError("MFA is not enabled for this user"));
    }

    const { decryptData } = await import("../utils/crypto.js");
    const decryptedSecret = decryptData(user.MFA.secret);

    const isOtpValid = speakeasy.totp.verify({
      secret: decryptedSecret,
      encoding: "base32",
      token: otp,
      window: 1,
    });

    if (!isOtpValid) {
      return next(new BadRequestError("Invalid MFA code"));
    }

    // Add mfaVerified to payload
    const accessToken = jwt.sign({ userId: user._id.toString(), role: user.roles, mfaVerified: true }, process.env.JWT_ACCESS_SECRET, {
      expiresIn: process.env.JWT_ACCESS_EXPIRES_IN || "15m",
    });

    const refreshToken = generateRefreshToken(user);
    setRefreshTokenCookie(res, refreshToken);

    user.refreshTokens.push(refreshToken);
    await user.save();

    return sendSuccess(res, 200, "MFA verified, logged in successfully", {
      accessToken,
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        role: user.roles,
      },
    });
  } catch (error) {
    next(new UnauthorizedError("Invalid or expired temporary token"));
  }
};

/**
 * Check authentication status.
 * @param {import('express').Request} req - Express request object.
 * @param {import('express').Response} res - Express response object.
 * @param {import('express').NextFunction} next - Express next middleware function.
 */
export const authStatus = (req, res, next) => {
  try {
    if (!req.user) {
      return next(new UnauthorizedError("Unauthorized"));
    }

    return sendSuccess(res, 200, "User is authenticated", { user: req.user });
  } catch (error) {
    next(error);
  }
};

/**
 * Logout the user.
 * Blacklists the access token and removes refresh token from DB and cookies.
 * @param {import('express').Request} req - Express request object.
 * @param {import('express').Response} res - Express response object.
 * @param {import('express').NextFunction} next - Express next middleware function.
 */
export const logout = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    let accessToken = null;
    if (authHeader && authHeader.startsWith("Bearer ")) {
      accessToken = authHeader.split(" ")[1];
    }
    const refreshToken = req.cookies.refreshToken;

    if (accessToken) {
      const decoded = jwt.decode(accessToken);
      if (decoded && decoded.exp) {
        await blacklistToken(accessToken, decoded.exp);
      }
    }

    if (req.user) {
      const user = await userModel.findById(req.user._id).select("+refreshTokens");
      if (user && refreshToken) {
        user.refreshTokens = user.refreshTokens.filter((t) => t !== refreshToken);
        await user.save();
      }
    }

    clearRefreshTokenCookie(res);
    return sendSuccess(res, 200, "Logged out successfully");
  } catch (error) {
    next(error);
  }
};

/**
 * Send an email verification link.
 * @param {import('express').Request} req - Express request object.
 * @param {import('express').Response} res - Express response object.
 * @param {import('express').NextFunction} next - Express next middleware function.
 */
export const sendVerificationEmail = async (req, res, next) => {
  try {
    const user = await userModel.findById(req.user._id);
    if (!user) {
      return next(new AppError("User not found", 404));
    }

    if (user.isAccountVerified) {
      return next(new BadRequestError("Email is already verified"));
    }

    const rawVerificationToken = crypto.randomBytes(32).toString("hex");
    const hashedVerificationToken = crypto.createHash("sha256").update(rawVerificationToken).digest("hex");

    user.emailVerificationToken = hashedVerificationToken;
    user.emailVerificationTokenExpires = Date.now() + 10 * 60 * 1000; // 10 mins
    await user.save();

    await emailLogic.sendVerificationEmail(user.email, rawVerificationToken);

    return sendSuccess(res, 200, "Verification email sent successfully");
  } catch (error) {
    next(error);
  }
};

/**
 * Confirm email verification.
 * @param {import('express').Request} req - Express request object.
 * @param {import('express').Response} res - Express response object.
 * @param {import('express').NextFunction} next - Express next middleware function.
 */
export const confirmEmailVerification = async (req, res, next) => {
  try {
    const { token } = req.body;
    if (!token) return next(new BadRequestError("Token is required"));

    const hashedToken = crypto.createHash("sha256").update(token).digest("hex");

    const user = await userModel.findOne({
      emailVerificationToken: hashedToken,
      emailVerificationTokenExpires: { $gt: Date.now() },
    });

    if (!user) {
      return next(new BadRequestError("Invalid or expired verification token"));
    }

    user.isAccountVerified = true;
    user.emailVerificationToken = undefined;
    user.emailVerificationTokenExpires = undefined;
    await user.save();

    return sendSuccess(res, 200, "Email verified successfully");
  } catch (error) {
    next(error);
  }
};

/**
 * Request password reset.
 * @param {import('express').Request} req - Express request object.
 * @param {import('express').Response} res - Express response object.
 * @param {import('express').NextFunction} next - Express next middleware function.
 */
export const requestPasswordReset = async (req, res, next) => {
  try {
    const { email } = req.body;
    const user = await userModel.findOne({ email });

    if (!user) {
      return sendSuccess(res, 200, "If an account with that email exists, we sent a password reset link.");
    }

    const resetToken = crypto.randomBytes(32).toString("hex");
    const hashedResetToken = crypto.createHash("sha256").update(resetToken).digest("hex");

    user.resetPasswordToken = hashedResetToken;
    user.resetPasswordTokenExpires = Date.now() + 15 * 60 * 1000;
    await user.save();

    try {
      await sendEmailVerifyPasswordReset(user.email, resetToken);
    } catch (err) {
      logger.error("Failed to send reset email:", { error: err.message, stack: err.stack });
    }

    return sendSuccess(res, 200, "If an account with that email exists, we sent a password reset link.");
  } catch (error) {
    next(error);
  }
};

/**
 * Confirm password reset.
 * @param {import('express').Request} req - Express request object.
 * @param {import('express').Response} res - Express response object.
 * @param {import('express').NextFunction} next - Express next middleware function.
 */
export const confirmPasswordReset = async (req, res, next) => {
  try {
    const { token, newPassword } = req.body;

    if (!token || !newPassword) {
      return next(new BadRequestError("Token and new password are required"));
    }

    if (newPassword.length < 8) {
      return next(new BadRequestError("Password must be at least 8 characters"));
    }

    const hashedToken = crypto.createHash("sha256").update(token).digest("hex");

    const user = await userModel.findOne({
      resetPasswordToken: hashedToken,
      resetPasswordTokenExpires: { $gt: Date.now() },
    });

    if (!user) {
      return next(new BadRequestError("Invalid or expired reset token"));
    }

    user.password = await hashPassword(newPassword);
    user.resetPasswordToken = undefined;
    user.resetPasswordTokenExpires = undefined;
    user.refreshTokens = [];
    user.lockUntil = undefined;
    user.failedLoginAttempts = 0;

    await user.save();

    return sendSuccess(res, 200, "Password has been reset successfully");
  } catch (error) {
    next(error);
  }
};

/**
 * Rotate access token using refresh token.
 * @param {import('express').Request} req - Express request object.
 * @param {import('express').Response} res - Express response object.
 * @param {import('express').NextFunction} next - Express next middleware function.
 */
export const rotateTokens = async (req, res, next) => {
  try {
    const refreshToken = req.cookies.refreshToken;

    if (!refreshToken) {
      return next(new UnauthorizedError("Refresh token required"));
    }

    const decoded = verifyRefreshToken(refreshToken);

    const user = await userModel.findById(decoded.userId).select("+refreshTokens +roles");

    if (!user || !user.refreshTokens.includes(refreshToken)) {
      return next(new UnauthorizedError("Invalid refresh token"));
    }

    const newAccessToken = generateAccessToken(user);

    return sendSuccess(res, 200, "Tokens refreshed successfully", {
      accessToken: newAccessToken,
      user: {
        id: user._id,
        email: user.email,
        role: user.roles,
      },
    });
  } catch (error) {
    clearRefreshTokenCookie(res);
    next(new UnauthorizedError("Invalid or expired refresh token"));
  }
};

export const oauthSuccess = (req, res) => {
  try {
    const user = req.user;
    if (!user) {
      return res.redirect(`${process.env.FRONTEND_URL || "http://localhost:5173"}/auth?error=OAuthFailed`);
    }

    if (user.MFA && user.MFA.enabled) {
      const tempToken = generateMfaToken(user);
      return res.redirect(`${process.env.FRONTEND_URL || "http://localhost:5173"}/auth?mfaRequired=true&token=${tempToken}`);
    }

    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);
    setRefreshTokenCookie(res, refreshToken);

    user.refreshTokens.push(refreshToken);
    user.save().then(() => {
      // Typically you'd pass accessToken to frontend via URL fragment or specialized redirect.
      // E.g. res.redirect(`${process.env.FRONTEND_URL}/auth-success?token=${accessToken}`);
      res.redirect(`${process.env.FRONTEND_URL || "http://localhost:5173"}/dashboard?token=${accessToken}`);
    });
  } catch (error) {
    res.redirect(`${process.env.FRONTEND_URL || "http://localhost:5173"}/auth?error=InternalServerError`);
  }
};
