import crypto from "crypto";
import bcrypt from "bcrypt";

export const generateOtp = () => {
  try {
    return crypto.randomInt(100000, 999999).toString();
  } catch (error) {
    throw new Error("Error generating OTP:", error);
  }
};

export const hashingOtp = async (plainOtp) => {
  try {
    const saltRounds = 10;
    return await bcrypt.hash(plainOtp, saltRounds);
  } catch (error) {
    throw new Error("Error at hashing OTP:", error);
  }
};

export const compareOtp = async (plainOtp, hashedOtp) => {
  try {
    return await bcrypt.compare(plainOtp, hashedOtp);
  } catch (error) {
    throw new Error("Error at comparing OTP:", error);
  }
};
