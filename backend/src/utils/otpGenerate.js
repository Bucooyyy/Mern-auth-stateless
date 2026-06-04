import crypto from "crypto";
import bcrypt from "bcrypt";
import logger from "../config/winston.logger";
import { InternalServerError } from "../errors/error";

export const generateOtp = () => {
  try {
    const otp = crypto.randomInt(100000, 999999).toString();
    return otp;
  } catch (error) {
    logger.error("Error generating OTP", {
      error: error.message,
      stack: error.stack,
    });
    throw new InternalServerError("Error on generating OTP");
  }
};

export const hashingOtp = async (plainOtp) => {
  try {
    const saltRounds = 10;
    const hashed = await bcrypt.hash(plainOtp, saltRounds);
    return hashed;
  } catch (error) {
    logger.error("Error hashing OTP", {
      error: error.message,
      stack: error.stack,
    });
    throw new InternalServerError("Error on hashing OTP");
  }
};

export const compareOtp = async (plainOtp, hashedOtp) => {
  try {
    const isValid = await bcrypt.compare(plainOtp, hashedOtp);
    return isValid;
  } catch (error) {
    logger.error("Error comparing OTP", {
      error: error.message,
      stack: error.stack,
    });
    throw new InternalServerError("Error on comparing OTP");
  }
};
