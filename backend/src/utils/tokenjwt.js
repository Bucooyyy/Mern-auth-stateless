import jwt, { decode } from "jsonwebtoken";
import redisClient from "../config/redis.config.js";

export const generateToken = (res, userId, role) => {
  try {
    const accessToken = jwt.sign({ userId, role, type: "access" }, process.env.JWT_SECRET, { expiresIn: "15m" });

    res.cookie("accessToken", accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 15 * 60 * 1000, // 15 menit
    });

    const refreshToken = jwt.sign({ userId, role, type: "refresh" }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: "90d" });

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 90 * 24 * 60 * 60 * 1000, // 90 hari
    });

    return { accessToken, refreshToken };
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Failed to generate token",
      error: error.message,
    });
  }
};

export const blackListToken = async (token) => {
  try {
    const decodedToken = jwt.decode(token);
    const expiry = decode.exp - Math.floor(Date.now() / 1000);
    await redisClient.setEx(`blacklist:${decodedToken}`, expiry, "revoked");
  } catch (error) {
    console.error("Error blacklisting token:", error);
    throw new Error("Failed to blacklist token");
  }
};

export const isTokenBlacklisted = async (token) => {
  // validasi input token
  if (!token || typeof token !== "string") {
    console.warn("Invalid token format");
    return true;
  }
  try {
    const isBlackListed = await redisClient.get(`blacklist:${token}`);
    return isBlackListed === "revoked";
  } catch (error) {
    console.error("Error checking token blacklist:", error);
    return true;
  }
};
