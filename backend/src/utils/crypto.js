import bcrypt from "bcrypt";
import crypto from "crypto";

export const hashPassword = async (password) => {
  try {
    const saltRounds = 12;
    return await bcrypt.hash(password, saltRounds);
  } catch (error) {
    throw new Error("Error at hashing password:", error);
  }
};

export const comparePassword = async (password, hashedPassword) => {
  try {
    return await bcrypt.compare(password, hashedPassword);
  } catch (error) {
    throw new Error("Error at compare password:", error);
  }
};

const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || "a".repeat(32); // Fallback key for demo purposes (32 bytes)
const ALGORITHM = "aes-256-gcm";

/**
 * Encrypts a string using AES-256-GCM.
 * @param {string} text - The text to encrypt.
 * @returns {string} The encrypted text (iv:authTag:encryptedData).
 */
export const encryptData = (text) => {
  if (!text) return text;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALGORITHM, Buffer.from(ENCRYPTION_KEY, "utf8").subarray(0, 32), iv);
  let encrypted = cipher.update(text, "utf8", "hex");
  encrypted += cipher.final("hex");
  const authTag = cipher.getAuthTag().toString("hex");
  return `${iv.toString("hex")}:${authTag}:${encrypted}`;
};

/**
 * Decrypts a string using AES-256-GCM.
 * @param {string} encryptedText - The text to decrypt (iv:authTag:encryptedData).
 * @returns {string} The decrypted text.
 */
export const decryptData = (encryptedText) => {
  if (!encryptedText) return encryptedText;
  const parts = encryptedText.split(":");
  if (parts.length !== 3) throw new Error("Invalid encrypted format");
  const iv = Buffer.from(parts[0], "hex");
  const authTag = Buffer.from(parts[1], "hex");
  const encryptedData = parts[2];
  const decipher = crypto.createDecipheriv(ALGORITHM, Buffer.from(ENCRYPTION_KEY, "utf8").subarray(0, 32), iv);
  decipher.setAuthTag(authTag);
  let decrypted = decipher.update(encryptedData, "hex", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
};
