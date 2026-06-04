import bcrypt from "bcrypt";
import crypto from "crypto";
import logger from "../config/winston.logger.js";
import { InternalServerError, BadRequestError } from "../errors/error.js";

export const hashPassword = async (password) => {
  try {
    const saltRounds = 12;
    const hashed = await bcrypt.hash(password, saltRounds);
    logger.debug("Password hashed successfully");
    return hashed;
  } catch (error) {
    logger.error("Error hashing password:", { error: error.message, stack: error.stack });
    throw new InternalServerError("Failed on hash password");
  }
};

export const comparePassword = async (password, hashedPassword) => {
  try {
    const isValid = await bcrypt.compare(password, hashedPassword);
    logger.debug(`Password comparison result: ${isValid}`);
    return isValid;
  } catch (error) {
    logger.error("Error comparing password:", { error: error.message, stack: error.stack });
    throw new InternalServerError("Failed on compare password");
  }
};

// AES-256-GCM encryption
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || "a".repeat(32); // 32 bytes
const ALGORITHM = "aes-256-gcm";

/**
 * Encrypts a string using AES-256-GCM.
 * @param {string} text - The text to encrypt.
 * @returns {string} The encrypted text (iv:authTag:encryptedData).
 */
export const encryptData = (text) => {
  if (!text) return text;
  try {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv(ALGORITHM, Buffer.from(ENCRYPTION_KEY, "utf8").subarray(0, 32), iv);
    let encrypted = cipher.update(text, "utf8", "hex");
    encrypted += cipher.final("hex");
    const authTag = cipher.getAuthTag().toString("hex");
    const result = `${iv.toString("hex")}:${authTag}:${encrypted}`;
    logger.debug("Data encrypted successfully");
    return result;
  } catch (error) {
    logger.error("Error encrypting data:", { error: error.message, stack: error.stack });
    throw new InternalServerError("Failed on encrypt data");
  }
};

/**
 * Decrypts a string using AES-256-GCM.
 * @param {string} encryptedText - The text to decrypt (iv:authTag:encryptedData).
 * @returns {string} The decrypted text.
 */
export const decryptData = (encryptedText) => {
  if (!encryptedText) return encryptedText;
  try {
    const parts = encryptedText.split(":");
    if (parts.length !== 3) {
      logger.warn("Invalid encrypted format provided", { preview: encryptedText.substring(0, 20) });
      throw new BadRequestError("Invalid encrypted format");
    }
    const iv = Buffer.from(parts[0], "hex");
    const authTag = Buffer.from(parts[1], "hex");
    const encryptedData = parts[2];
    const decipher = crypto.createDecipheriv(ALGORITHM, Buffer.from(ENCRYPTION_KEY, "utf8").subarray(0, 32), iv);
    decipher.setAuthTag(authTag);
    let decrypted = decipher.update(encryptedData, "hex", "utf8");
    decrypted += decipher.final("utf8");
    logger.debug("Data decrypted successfully");
    return decrypted;
  } catch (error) {
    if (error instanceof BadRequestError) throw error;
    logger.error("Error decrypting data:", { error: error.message, stack: error.stack });
    throw new InternalServerError("Failed on decrypt data");
  }
};
