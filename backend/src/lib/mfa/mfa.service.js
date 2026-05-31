import speakeasy from "speakeasy";
import qrcode from "qrcode";
import logger from "../../config/winston.logger.js";
import { encryptData, decryptData } from "../../utils/crypto.js";

const ISSUER = "MernAuthV.me";

/**
 * Generates an MFA secret for the user.
 * @param {string} email - User's email to embed in the app name.
 * @returns {object} The speakeasy secret object (base32, otpauth_url, etc).
 */
export const generateSecret = (email) => {
  return speakeasy.generateSecret({
    name: `${ISSUER} (${email})`,
    issuer: ISSUER,
    length: 20,
  });
};

/**
 * Generates a QR Code data URL from an otpauth URL.
 * @param {string} otpauthUrl - The otpauth URL to encode.
 * @returns {Promise<string>} The base64 data URL.
 */
export const generateQRCode = async (otpauthUrl) => {
  try {
    return await qrcode.toDataURL(otpauthUrl);
  } catch (error) {
    logger.error("Failed to generate QR code", { error: error.message });
    throw error;
  }
};

/**
 * Verifies a TOTP token against a secret.
 * @param {string} secret - The base32 secret.
 * @param {string} token - The 6-digit code.
 * @param {number} window - The window of verification (default 1).
 * @returns {boolean} True if verified, false otherwise.
 */
export const verifyToken = (secret, token, window = 1) => {
  return speakeasy.totp.verify({
    secret,
    encoding: "base32",
    token: String(token),
    window,
  });
};

/**
 * Encrypts an MFA secret for storage.
 * @param {string} secret - Plaintext base32 secret.
 * @returns {string} Encrypted secret.
 */
export const encryptSecret = (secret) => {
  return encryptData(secret);
};

/**
 * Decrypts an MFA secret from storage.
 * @param {string} encryptedSecret - Encrypted secret string.
 * @returns {string} Decrypted base32 secret.
 */
export const decryptSecret = (encryptedSecret) => {
  return decryptData(encryptedSecret);
};
