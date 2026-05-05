import speakeasy, { otpauthURL } from "speakeasy";
import qrcode from "qrcode";
import logger from "../../config/winston.logger.js";

const ISSUER = "AuthApp";

export const generateSecret = (email) => {
  const secret = speakeasy.generateSecret({
    name: `${ISSUER}:${email}`,
    issuer: ISSUER,
    length: 20,
  });
  return secret;
};

export const generateQRCode = async (otpauthUrl) => {
  try {
    return await qrcode.toDataURL(otpauthUrl);
  } catch (error) {
    logger.error("Failed to generate QR code", { error: error.message });
    throw error;
  }
};

export const verifyToken = (secret, token) => {
  return speakeasy.totp.verify({
    secret,
    encoding: "base32",
    token: String(token),
    window: 1,
  });
};
