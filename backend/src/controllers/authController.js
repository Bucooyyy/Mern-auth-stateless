import userModel from "../models/user.model.js";
import { hashPassword, comparePassword } from "../utils/crypto.js";
import { generateOtp, hashingOtp, compareOtp } from "../utils/otpGenerate.js";
import { blackListToken, generateToken, isTokenBlacklisted, verifyToken } from "../utils/tokenjwt.js";
import { logSecurityEvent } from "../lib/winston.logger.js";

import jwt from "jsonwebtoken";
// Registration logic
export const register = async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ success: false, message: "All fields are required" });
    }

    const existingUser = await userModel.findOne({ email });

    if (existingUser) {
      logSecurityEvent("REGISTRATION_BLOCKED", null, existingUser._id, req.ip, req.get("User-Agent"), { reason: "EMAIL_EXISTS", email });
      return res.status(409).json({ success: false, message: "User already exists" });
    }

    const hashedPassword = await hashPassword(password);
    // const plainOtp = generateOtp();
    // const hashedOtp = await hashingOtp(plainOtp);

    const user = new userModel({
      name,
      email,
      password: hashedPassword,
      // isAccountVerified: true,
      // emailVerificationToken: hashedOtp,
      isMfaEnabled: false,
      role: "freeUser", // Default role
    });

    if (user) {
      await user.save();
      console.log("User registered successfully:", user);
      generateToken(res, user._id, user.role);
      // await sendVerificationEmail(user.email, plainOtp);
      logSecurityEvent("REGISTRATION_SUCCESS", user._id, req.ip, req.get("User-Agent"));
      return res.status(201).json({
        success: true,
        message: "User registered successfully",
        data: {
          user: {
            id: user._id,
            email: user.email,
            name: user.name,
            role: user.role,
            // isAccountVerified: user.isAccountVerified,
            createdAt: user.createdAt,
          },
        },
      });
    }
  } catch (error) {
    logSecurityEvent("REGISTRATION_ERROR", null, req.ip, req.get("User-Agent"), {
      error: error.message,
    });
    res.status(500).json({
      success: false,
      message: "Internal Server Error",
      error: error.message,
    });
  }
};

export const login = async (req, res) => {
  const { email, password, token } = req.body;

  if (!email || !password) {
    return res.status(400).json({ success: false, message: "All fields must be fulfilled" });
  }

  try {
    const user = await userModel.findOne({ email }).select("+password +MFA.enabled +MFA.secret");

    if (!user) {
      logSecurityEvent("LOGIN_FAILED", null, req.ip, req.get("User-Agent"), {
        reason: "USER_NOT_FOUND",
        email: email,
      });
      return res.status(401).json({ success: false, message: "Incorrect email or password" });
    }
    const isPasswordValid = await comparePassword(password, user.password);

    if (!isPasswordValid) {
      return res.status(400).json({ success: false, message: "Incorrect password" });
    }

    if (user.MFA.enabled) {
      const mFATokenVeirfy = speakeasy.totp.verify({
        secret: user.MFA.secret,
        encoding: "base32",
      });
    }
    const {
      accessToken,
      // refreshToken
    } = generateToken(res, user._id);
    const decoded = jwt.decode(
      accessToken,
      //  refreshToken,
      { complete: true }
    );
    console.log("decoded token:", decoded);

    await user.save();
    console.log("User logged in successfully:", user);
    res.status(200).json({
      success: true,
      message: "logged in successfully",
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Internal Server Error",
      error: error.message,
    });
  }
};

export const authStatus = (req, res) => {
  try {
    if (!req.user) {
      return res.status(401).json({ success: false, message: "Unauthorized" });
    }

    res.status(200).json({
      success: true,
      user: req.user,
      message: "User is authenticated",
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Internal Server Error",
      error: error.message,
    });
  }
};

export const logout = async (req, res) => {
  const {
    accessToken,
    // refreshToken
  } = req.cookies.accessToken;

  try {
    if (accessToken) await blackListToken(accessToken);
    // if (refreshToken) await blackListToken(refreshToken)

    res.clearCookie("accessToken", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
    });

    // res.clearCookie("refreshToken", {
    //   httpOnly: true,
    //   secure: process.env.NODE_ENV === "production",
    //   sameSite: "strict",
    // });

    res.status(200).json({ success: true, message: "Logged out successfully" });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Internal Server Error",
      error: error.message,
    });
  }
};

export const sendVerificationEmail = async (req, res) => {
  try {
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Internal Server Error",
      error: error.message,
    });
  }
};

export const confirmEmailVerification = async (req, res) => {
  try {
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Internal Server Error",
      error: error.message,
    });
  }
};

export const requestPasswordReset = async (req, res) => {
  try {
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Internal Server Error",
      error: error.message,
    });
  }
};

export const confirmPasswordReset = async (req, res) => {
  try {
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Internal Server Error",
      error: error.message,
    });
  }
};

export const rotateTokens = async (req, res) => {
  try {
    const token = req.cookies.accessToken;

    if (!token) {
      return res.status(401).json({ success: false, message: "Access token required" });
    }

    let checkingToken = verifyToken(token);

    if (!checkingToken) {
      return res.status(403).json({ success: false, message: "Invalid or expired token" });
    }

    const isBlackListed = await isTokenBlacklisted(token);

    if (isBlackListed) {
      return res.status(403).json({ success: false, message: "Token has been revoked" });
    }

    const user = await userModel.findById(checkingToken.id);

    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    await blackListToken(token);

    const newAccessToken = generateToken(res, user._id);

    return res.status(200).json({
      success: true,
      message: "Tokens refreshed successfully",
      accessToken: newAccessToken,
      user: {
        id: user._id,
        email: user.email,
      },
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Internal Server Error",
      error: error.message,
    });
  }
};

export const debugBlaclListToken = async (req, res) => {
  try {
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Internal Server Error",
      error: error.message,
    });
  }
};
