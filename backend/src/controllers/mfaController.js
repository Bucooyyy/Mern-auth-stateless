import User from "../models/user.model.js";
import * as mfaService from "../utils/mfa.service.js";
import { generateAccessToken, generateRefreshToken, verifyMfaToken, setRefreshTokenCookie } from "../utils/tokenjwt.js";
import { addRefreshToken } from "../utils/refreshToken.service.js";
import { sendMFASetupEmail } from "../utils/mailsender.js";
import { AppError, BadRequestError, InternalServerError, UnauthorizedError } from "../errors/error.js";
import { sendSuccess } from "../utils/response.js";
import logger from "../config/winston.logger.js";

export const setupMFA = async (req, res, next) => {
  try {
    const user = req.user;

    if (user.MFA?.enabled) {
      throw new BadRequestError("MFA is already enabled for this account");
    }

    const secret = mfaService.generateSecret(user.email);
    const qrCodeUrl = await mfaService.generateQRCode(secret.otpauth_url);

    await User.findByIdAndUpdate(user._id, {
      "MFA.tempSecret": mfaService.encryptSecret(secret.base32),
    });

    logger.info("MFA setup initiated", { userId: user._id, email: user.email });

    return sendSuccess(res, 200, "MFA setup initiated. Scan the QR code with your authenticator app.", {
      qrCode: qrCodeUrl,
      secret: secret.base32,
    });
  } catch (error) {
    next(error);
  }
};

export const enableMFA = async (req, res, next) => {
  try {
    const { token } = req.body;
    const user = await User.findById(req.user._id).select("+MFA.tempSecret +MFA.secret");

    if (!user) {
      throw new AppError("User not found", 404);
    }

    if (!user.MFA?.tempSecret) {
      throw new BadRequestError("MFA setup not initiated. Please start the MFA setup process first.");
    }

    if (user.MFA?.enabled) {
      throw new BadRequestError("MFA is already enabled");
    }

    const decryptedTempSecret = mfaService.decryptSecret(user.MFA.tempSecret);
    const isVerified = mfaService.verifyToken(decryptedTempSecret, token);

    if (!isVerified) {
      throw new UnauthorizedError("Invalid or expired MFA token");
    }

    const plainBackupCodes = mfaService.generateBackupCodes();
    const encryptedBackupCodes = await mfaService.hashBackupCodes(plainBackupCodes);

    user.MFA.secret = mfaService.encryptSecret(decryptedTempSecret);
    user.MFA.tempSecret = undefined;
    user.MFA.enabled = true;
    user.MFA.BackupCodes = encryptedBackupCodes;
    await user.save();

    await sendMFASetupEmail(user.email);

    logger.info("MFA enabled for user", { userId: user._id, email: user.email });

    return sendSuccess(res, 200, "MFA enabled successfully", {
      user: { id: user._id, email: user.email, mfaEnabled: true },
      backupCodes: plainBackupCodes, // Only return plain backup codes once at setup
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Disables MFA for the user. Requires a valid MFA token to confirm.
 */
export const disableMFA = async (req, res, next) => {
  try {
    const { token, backupCode } = req.body;
    const user = await User.findById(req.user._id).select("+MFA.secret +MFA.enabled +MFA.BackupCodes");

    if (!user.MFA?.enabled) {
      throw new BadRequestError("MFA is not enabled on this account");
    }

    let isVerified = false;
    if (token) {
      const decryptedSecret = mfaService.decryptSecret(user.MFA.secret);
      isVerified = mfaService.verifyToken(decryptedSecret, token, 1);
    } else if (backupCode && user.MFA.BackupCodes?.length) {
      isVerified = await mfaService.verifyBackupCode(backupCode, user.MFA.BackupCodes);
    }

    if (!isVerified) {
      throw new BadRequestError("Invalid MFA token or backup code");
    }

    user.MFA.secret = undefined;
    user.MFA.tempSecret = undefined;
    user.MFA.enabled = false;
    user.MFA.verifiedAt = undefined;
    user.MFA.lastUsedAt = undefined;
    user.MFA.BackupCodes = [];
    await user.save();

    logger.info("MFA disabled for user", { userId: user._id, email: user.email });

    return sendSuccess(res, 200, "MFA disabled successfully", {
      user: { id: user._id, email: user.email, mfaEnabled: false },
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Verifies the MFA token during enrollment.
 * If successful, promotes tempSecret to secret and enables MFA.
 */

export const verifyMFA = async (req, res, next) => {
  try {
    const { mfaToken, token, backupCode } = req.body;

    if (!mfaToken) {
      throw new BadRequestError("MFA setup token is required");
    }
    if (!token && !backupCode) {
      throw new BadRequestError("MFA token or backup code is required");
    }

    if (typeof token !== "string" || !/^\d{6}$/.test(token)) {
      throw new BadRequestError("TOTP token must be a 6-digit numeric string");
    }

    let payload;
    try {
      payload = verifyMfaToken(mfaToken);
    } catch (error) {
      throw new UnauthorizedError("Invalid or expired MFA session token");
    }

    if (payload.purpose !== "mfa_verification") {
      throw new UnauthorizedError("Invalid MFA session token purpose");
    }

    const user = await User.findById(payload.userId).select("+MFA.secret +MFA.enabled +MFA.BackupCodes");

    if (!user) {
      throw new UnauthorizedError("User not found");
    }

    if (!user.MFA?.enabled) {
      throw new BadRequestError("MFA is not enabled for this account");
    }

    let isVerified = false;
    if (token) {
      const decryptedSecret = mfaService.decryptSecret(user.MFA.secret);
      isVerified = mfaService.verifyToken(decryptedSecret, token, 3);
    } else if (backupCode) {
      isVerified = await mfaService.verifyBackupCode(backupCode, user.MFA.BackupCodes);
      if (isVerified) {
        const updated = await mfaService.removeUsedBackupCode(backupCode, user.MFA.BackupCodes);
        await user.save();
        logger.info("MFA backup code used for MFA", { userId: user._id, email: user.email });
      }
    }

    if (!isVerified) {
      throw new BadRequestError("Invalid or expired MFA token/backup code");
    }

    user.MFA.lastUsedAt = new Date();
    await user.save();

    const accessToken = generateAccessToken(user, true);
    const refreshToken = generateRefreshToken(user);
    await addRefreshToken(user._id, refreshToken);
    setRefreshTokenCookie(res, refreshToken);

    logger.info("MFA verified, user logged in", { userId: user._id, email: user.email });

    return sendSuccess(res, 200, "MFA verified successfully", {
      user: { id: user._id, accessToken, email: user.email },
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Resets MFA (for admins or recovery, optional).
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
