import speakeasy from "speakeasy";
import qrcode from "qrcode";

import userModel from "../models/user.model.js";

export const enableMFA = async (req, res, next) => {
  // MFA enable logic
  try {
    console.log("=== enableMFA ===");

    const user = req.user;
    console.log("user:", user);

    const tempSecret = speakeasy.generateSecret({
      name: `MernAuthV.me (${user.email})`,
    });

    const qrCodeUrl = await qrcode.toDataURL(tempSecret.otpauth_url);

    user.MFA.tempSecret = tempSecret.base32;
    await user.save();

    res.status(200).json({
      success: true,
      qrCode: qrCodeUrl,
      secret: tempSecret.base32,
      message: "Scan the QR code with your authenticator app",
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Internal Server Error",
      error: error.message,
    });
    // next(error);
  }
};

export const disableMFA = (req, res) => {
  // MFA disable logic
  try {
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Internal Server Error",
      error: error.message,
    });
  }
};

export const verifyMFA = async (req, res) => {
  // Verify MFA logic
  try {
    console.log("=== verifyMFA ===");
    const { token } = req.body;
    const user = await userModel.findById(req.user._id).select("+MFA.secret +MFA.tempSecret");

    console.log("user:", user, "token:", token);
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    if (!user.MFA.tempSecret) {
      return res.status(400).json({ success: false, message: "MFA is not in the setup process" });
    }
    const verified = speakeasy.totp.verify({
      secret: user.MFA.tempSecret,
      encoding: "base32",
      token: token,
      window: 3, // Allow a window of 3 time steps (90 seconds)
    });

    if (verified) {
      user.MFA.enabled = true;
      user.MFA.secret = user.MFA.tempSecret;
      user.MFA.tempSecret = undefined;
      await user.save();

      res.json({
        success: true,
        message: "MFA verified successfully",
        user: user,
      });
    } else {
      res.status(400).json({
        success: false,
        message: "Invalid or expired MFA token",
      });
    }
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Internal Server Error",
      error: error.message,
    });
  }
};

export const resetMFA = (req, res) => {
  // Reset MFA logic
  try {
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Internal Server Error",
      error: error.message,
    });
  }
};
