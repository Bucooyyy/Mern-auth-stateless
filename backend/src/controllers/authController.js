import userModel from "../models/user.model.js";
import { hashPassword, comparePassword } from "../utils/crypto.js";
import { generateOtp, hashingOtp, compareOtp } from "../utils/otpgenerate.js";
import { generateToken } from "../utils/tokenjwt.js";

// Registration logic
export const register = async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ success: false, message: "All fields are required" });
    }

    // if (!validator.isEmail(email)) {
    //   return res.status(400).json({
    //     success: false,
    //     message: "Please provide a valid email address"
    //   });
    // }

    const existingUser = await userModel.findOne({ email });

    if (existingUser) {
      return res.status(400).json({ success: false, message: "User already exists" });
    }

    const hashedPassword = await hashPassword(password);
    // const plainOtp = generateOtp();
    // const hashedOtp = await hashingOtp(plainOtp);

    const newUser = new userModel({
      name,
      email,
      password: hashedPassword,
      // emailVerificationToken: hashedOtp,
      isMfaEnabled: false,
      role: "freeUser", // Default role
    });

    if (newUser) {
      await newUser.save();
      console.log("User registered successfully:", newUser);
      generateToken(res, newUser._id, newUser.role);
      // await sendVerificationEmail(newUser.email, plainOtp);
      return res.status(201).json({ success: true, message: "User registered successfully", user: newUser });
    }
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Internal Server Error",
      error: error.message,
    });
  }
};

export const login = async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ success: false, message: "All fields must be fulfilled" });
  }

  try {
    const user = await userModel.findOne({ email });

    if (!user) {
      return res.status(400).json({ success: false, message: "Incorrect email or password" });
    }
    const isPasswordValid = await comparePassword(password, user.password);

    if (!isPasswordValid) {
      return res.status(400).json({ success: false, message: "Incorrect password" });
    }

    generateTokenAndSetCookie(res, user._id);
    await user.save();

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

export const logout = (req, res) => {
  try {
    res.clearCookie("token", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
    });

    res.status(200).json({ success: true, message: "Logged out successfully" });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Internal Server Error",
      error: error.message,
    });
  }
};

export const sendVerificationEmail = async (req, res) => {};

export const confirmEmailVerification = async (req, res) => {};

export const requestPasswordReset = async (req, res) => {};

export const confirmPasswordReset = async (req, res) => {};

export const setupMFA = (req, res) => {
  // 2FA setup logic
  try {
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Internal Server Error",
      error: error.message,
    });
  }
};

export const verifyMFA = (req, res) => {
  // Verify 2FA logic
  try {
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Internal Server Error",
      error: error.message,
    });
  }
};

export const resetMFA = (req, res) => {
  // Reset 2FA logic
  try {
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Internal Server Error",
      error: error.message,
    });
  }
};
