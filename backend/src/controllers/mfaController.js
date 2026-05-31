import userModel from "../models/user.model.js";
import { AppError, BadRequestError, InternalServerError } from "../errors/error.js";
import { sendSuccess, sendError } from "../utils/response.js";
import * as mfaService from "../lib/mfa/mfa.service.js";

/**
 * Initiates the MFA enrollment process for a user.
 * Generates a temporary secret, saves it in Redis or user DB, and returns a QR code.
 * @param {import('express').Request} req - Express request object.
 * @param {import('express').Response} res - Express response object.
 * @param {import('express').NextFunction} next - Express next middleware function.
 */
export const enableMFA = async (req, res, next) => {
  try {
    const user = req.user;

    // Check if MFA is already fully enabled
    if (user.MFA && user.MFA.enabled) {
      return next(new BadRequestError("MFA is already enabled"));
    }

    // Generate secret and QR code
    const secret = mfaService.generateSecret(user.email);
    const qrCodeUrl = await mfaService.generateQRCode(secret.otpauth_url);

    // Save encrypted tempSecret in user DB
    const dbUser = await userModel.findById(user._id);
    if (!dbUser) {
      return next(new AppError("User not found", 404));
    }

    if (!dbUser.MFA) {
      dbUser.MFA = {};
    }
    
    dbUser.MFA.tempSecret = mfaService.encryptSecret(secret.base32);
    await dbUser.save();

    return sendSuccess(res, 200, "Scan the QR code with your authenticator app", {
      qrCode: qrCodeUrl,
      secret: secret.base32,
    });
  } catch (error) {
    next(new InternalServerError(error.message));
  }
};

/**
 * Verifies the MFA token during enrollment.
 * If successful, promotes tempSecret to secret and enables MFA.
 * @param {import('express').Request} req - Express request object.
 * @param {import('express').Response} res - Express response object.
 * @param {import('express').NextFunction} next - Express next middleware function.
 */
export const verifyMFA = async (req, res, next) => {
  try {
    const { token } = req.body;
    if (!token) {
      return next(new BadRequestError("MFA token is required"));
    }

    const user = await userModel.findById(req.user._id).select("+MFA.secret +MFA.tempSecret +MFA.enabled");
    
    if (!user) {
      return next(new AppError("User not found", 404));
    }

    if (!user.MFA || !user.MFA.tempSecret) {
      return next(new BadRequestError("MFA is not in the setup process"));
    }

    const decryptedTempSecret = mfaService.decryptSecret(user.MFA.tempSecret);
    const isVerified = mfaService.verifyToken(decryptedTempSecret, token, 3);

    if (isVerified) {
      user.MFA.enabled = true;
      user.MFA.secret = mfaService.encryptSecret(decryptedTempSecret);
      user.MFA.tempSecret = undefined;
      // sync the top level isMFAEnabled with MFA.enabled
      user.isMFAEnabled = true;
      await user.save();

      return sendSuccess(res, 200, "MFA verified successfully", {
        user: { id: user._id, email: user.email, mfaEnabled: true },
      });
    } else {
      return next(new BadRequestError("Invalid or expired MFA token"));
    }
  } catch (error) {
    next(new InternalServerError(error.message));
  }
};

/**
 * Disables MFA for the user. Requires a valid MFA token to confirm.
 * @param {import('express').Request} req - Express request object.
 * @param {import('express').Response} res - Express response object.
 * @param {import('express').NextFunction} next - Express next middleware function.
 */
export const disableMFA = async (req, res, next) => {
  try {
    const { token } = req.body;
    if (!token) {
      return next(new BadRequestError("MFA token is required to disable MFA"));
    }

    const user = await userModel.findById(req.user._id).select("+MFA.secret +MFA.enabled");
    
    if (!user || !user.MFA || !user.MFA.enabled) {
      return next(new BadRequestError("MFA is not enabled"));
    }

    const decryptedSecret = mfaService.decryptSecret(user.MFA.secret);
    const isVerified = mfaService.verifyToken(decryptedSecret, token, 1);

    if (!isVerified) {
      return next(new BadRequestError("Invalid MFA token"));
    }

    user.MFA.enabled = false;
    user.MFA.secret = undefined;
    user.MFA.tempSecret = undefined;
    user.isMFAEnabled = false;
    await user.save();

    return sendSuccess(res, 200, "MFA disabled successfully");
  } catch (error) {
    next(new InternalServerError(error.message));
  }
};

/**
 * Resets MFA (for admins or recovery, optional).
 * @param {import('express').Request} req - Express request object.
 * @param {import('express').Response} res - Express response object.
 * @param {import('express').NextFunction} next - Express next middleware function.
 */
export const resetMFA = async (req, res, next) => {
  try {
    // In a real scenario, this would check if req.user is admin, etc.
    // For now, this is a placeholder or minimal implementation.
    return sendSuccess(res, 200, "MFA reset successfully");
  } catch (error) {
    next(new InternalServerError(error.message));
  }
};
