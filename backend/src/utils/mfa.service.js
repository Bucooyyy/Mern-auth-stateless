import speakeasy from "speakeasy";
import qrcode from "qrcode";
import bcrypt from "bcrypt";
import crypto from "crypto";
import logger from "../config/winston.logger.js";
import { encryptData, decryptData } from "./crypto.js";

/**
 * Generates an MFA secret for the user.
 * @param {string} email - User's email to embed in the app name.
 * @returns {object} The speakeasy secret object (base32, otpauth_url, etc).
 */
export const generateSecret = (email) => {
  return speakeasy.generateSecret({
    name: `${process.env.ISSUER} (${email})`,
    issuer: process.env.ISSUER,
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
 * Generate backup codes (plain text) for MFA recovery.
 * @param {number} count - Jumlah kode (default 8)
 * @param {number} length - Panjang tiap kode (default 8)
 * @returns {string[]} Array kode backup plain
 */
export const generateBackupCodes = (count = 8, length = 8) => {
  const codes = [];
  for (let i = 0; i < count; i++) {
    const code = crypto
      .randomBytes(Math.ceil(length / 2))
      .toString("hex")
      .slice(0, length)
      .toUpperCase();
    codes.push(code);
  }
  return codes;
};

/**
 * Hash backup codes (bcrypt) untuk disimpan di DB.
 * @param {string[]} plainCodes
 * @returns {Promise<string[]>}
 */
export const hashBackupCodes = async (plainCodes) => {
  const saltRounds = 10;
  return await Promise.all(plainCodes.map((code) => bcrypt.hash(code, saltRounds)));
};

/**
 * Verifikasi apakah backup code cocok dengan salah satu hash yang tersimpan.
 * @param {string} inputCode - Kode dari user
 * @param {string[]} hashedCodes - Array hash dari DB
 * @returns {Promise<boolean>}
 */
export const verifyBackupCode = async (inputCode, hashedCodes) => {
  for (const hash of hashedCodes) {
    if (await bcrypt.compare(inputCode, hash)) return true;
  }
  return false;
};

/**
 * Hapus backup code yang sudah digunakan (return array baru tanpa hash tsb).
 * @param {string} inputCode - Kode yang digunakan
 * @param {string[]} hashedCodes - Array hash saat ini
 * @returns {Promise<string[]>}
 */
export const removeUsedBackupCode = async (inputCode, hashedCodes) => {
  for (let i = 0; i < hashedCodes.length; i++) {
    if (await bcrypt.compare(inputCode, hashedCodes[i])) {
      const newCodes = [...hashedCodes];
      newCodes.splice(i, 1);
      return newCodes;
    }
  }
  return hashedCodes;
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
