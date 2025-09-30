import jwt, { decode } from "jsonwebtoken";
import redisClient from "../config/redis.config.js";

export const generateToken = (res, userId, role) => {
  try {
    const accessToken = jwt.sign({ id: userId, role, type: "access" }, process.env.JWT_SECRET, { expiresIn: "15m" });

    res.cookie("accessToken", accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 90 * 24 * 60 * 60 * 1000, // 90 hari
      // maxAge: 15 * 60 * 1000, // 15 menit
    });

    // const refreshToken = jwt.sign({ id: userId, role, type: "refresh" }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: "90d" });

    // res.cookie("refreshToken", refreshToken, {
    //   httpOnly: true,
    //   secure: process.env.NODE_ENV === "production",
    //   sameSite: "strict",
    //   maxAge: 90 * 24 * 60 * 60 * 1000, // 90 hari
    // });

    return {
      accessToken,
      // refreshToken
    };
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Failed to generate token",
      error: error.message,
    });
  }
};

export const verifyToken = (token) => {
  try {
    const isTokenVerified = jwt.verify(token, process.env.JWT_SECRET);
    console.log("Token verified:", isTokenVerified);
    return isTokenVerified;
  } catch (error) {
    console.error("Error verifying token:", error);
    throw new Error("Failed to verify token");
  }
};

export const blackListToken = async (accessToken, refreshToken) => {
  console.log("===BlacklistToken===");

  try {
    if (
      !accessToken
      // && !refreshToken
    ) {
      return { success: false, message: "No tokens provided" };
    }

    const decodedToken = jwt.decode(accessToken);
    const expiry = decodedToken.exp - Math.floor(Date.now() / 1000);
    if (expiry <= 0) {
      console.warn("Token already expired, no need to blacklist");
    }

    await redisClient.setEx(`blacklist:${decodedToken}`, expiry, "revoked");
    console.log("Token blacklisted successfully");
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
