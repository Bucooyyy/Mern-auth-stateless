import User from "../models/user.model.js";
import * as mfaService from "../lib/mfa/mfa.service.js";
import { generateAccessToken, generateRefreshToken, verifyMfaToken, setRefreshTokenCookie } from "../utils/tokenjwt.js";
import { addRefreshToken } from "../lib/token-services/refreshToken.service.js";
import { sendMFASetupEmail } from "../lib/email/mailsender.js";
import { AppError, BadRequestError, InternalServerError, UnauthorizedError } from "../errors/error.js";
import { sendSuccess } from "../utils/response.js";
import logger from "../config/winston.logger.js";

export const mfaSetup = async (req, res) => {
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
};

export const enableMFA = async (req, res) => {
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

  if (isVerified) {
    user.MFA.secret = mfaService.encryptSecret(decryptedTempSecret);
    user.MFA.tempSecret = undefined;
    user.MFA.enabled = true;
    await user.save();

    await sendMFASetupEmail(user.email);

    logger.info("MFA enabled for user", { userId: user._id, email: user.email });

    return sendSuccess(res, 200, "MFA enabled successfully", {
      user: { id: user._id, email: user.email, mfaEnabled: true },
    });
  } else {
    throw new UnauthorizedError("Invalid or expired MFA token");
  }
};

/**
 * Disables MFA for the user. Requires a valid MFA token to confirm.
 */
export const disableMFA = async (req, res) => {
  const { token } = req.body;
  const user = await User.findById(req.user._id).select("+MFA.secret +MFA.enabled");

  if (!token) {
    throw new BadRequestError("MFA token is required to disable MFA");
  }

  if (!user.MFA?.enabled) {
    throw new BadRequestError("MFA is not enabled on this account");
  }

  const decryptedSecret = mfaService.decryptSecret(user.MFA.secret);
  const isVerified = mfaService.verifyToken(decryptedSecret, token, 1);

  if (!isVerified) {
    throw new BadRequestError("Invalid MFA token");
  }

  user.MFA.secret = undefined;
  user.MFA.tempSecret = undefined;
  user.MFA.enabled = false;
  await user.save();

  logger.info("MFA disabled for user", { userId: user._id, email: user.email });

  return sendSuccess(res, 200, "MFA disabled successfully", {
    user: { id: user._id, email: user.email, mfaEnabled: false },
  });
};

/**
 * Verifies the MFA token during enrollment.
 * If successful, promotes tempSecret to secret and enables MFA.
 */

export const verifyMFA = async (req, res) => {
  const { mfaToken, token } = req.body;

  if (!mfaToken) {
    throw new BadRequestError("MFA setup token is required");
  }
  if (!token) {
    throw new BadRequestError("MFA token is required");
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

  const user = await userModel.findById(payload.userId).select("+MFA.secret +MFA.enabled");

  if (!user) {
    throw new UnauthorizedError("User not found");
  }

  if (!user.MFA?.enabled) {
    throw new BadRequestError("MFA is not enabled for this account");
  }

  if (!user.MFA?.tempSecret) {
    throw new BadRequestError("MFA is not configured for this account");
  }

  const decryptedTempSecret = mfaService.decryptSecret(user.MFA.tempSecret);
  const isVerified = mfaService.verifyToken(decryptedTempSecret, token, 3);

  if (isVerified) {
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);
    await addRefreshToken(user._id, refreshToken);
    setRefreshTokenCookie(res, refreshToken);
    await user.save();

    logger.info("MFA verified, user logged in", { userId: user._id, email: user.email });

    return sendSuccess(res, 200, "MFA verified successfully", {
      user: { id: user._id, accessToken, email: user.email },
    });
  } else {
    return next(new BadRequestError("Invalid or expired MFA token"));
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
