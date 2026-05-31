import userModel from "../models/user.model.js";
import { AppError, BadRequestError, InternalServerError } from "../errors/error.js";
import { sendSuccess } from "../utils/response.js";
import { hashPassword, comparePassword } from "../utils/crypto.js";

/**
 * Get the current user's profile.
 * @param {import('express').Request} req - Express request object.
 * @param {import('express').Response} res - Express response object.
 * @param {import('express').NextFunction} next - Express next middleware function.
 */
export const getProfile = async (req, res, next) => {
  try {
    const user = await userModel.findById(req.user._id);
    if (!user) {
      return next(new AppError("User not found", 404));
    }
    return sendSuccess(res, 200, "User profile retrieved successfully", { user });
  } catch (error) {
    next(new InternalServerError(error.message));
  }
};

/**
 * Update the user's profile (name, email).
 * If email is changed, it requires re-verification.
 * @param {import('express').Request} req - Express request object.
 * @param {import('express').Response} res - Express response object.
 * @param {import('express').NextFunction} next - Express next middleware function.
 */
export const updateProfile = async (req, res, next) => {
  try {
    const { name, email } = req.body;
    const user = await userModel.findById(req.user._id);

    if (!user) {
      return next(new AppError("User not found", 404));
    }

    let emailChanged = false;

    if (name) user.name = name;
    if (email && email !== user.email) {
      // Check if email already in use
      const existingEmail = await userModel.findOne({ email });
      if (existingEmail) {
        return next(new BadRequestError("Email is already in use by another account"));
      }
      user.email = email;
      user.isAccountVerified = false; // Require re-verification
      emailChanged = true;
    }

    await user.save();

    return sendSuccess(res, 200, "Profile updated successfully", {
      user,
      emailChanged,
      message: emailChanged ? "Profile updated. Please verify your new email." : "Profile updated."
    });
  } catch (error) {
    next(new InternalServerError(error.message));
  }
};

/**
 * Update the user's password. Requires current password to be verified.
 * @param {import('express').Request} req - Express request object.
 * @param {import('express').Response} res - Express response object.
 * @param {import('express').NextFunction} next - Express next middleware function.
 */
export const updatePassword = async (req, res, next) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return next(new BadRequestError("Current and new passwords are required"));
    }

    const user = await userModel.findById(req.user._id).select("+password");

    if (!user) {
      return next(new AppError("User not found", 404));
    }

    if (!user.password && user.oauth && Object.values(user.oauth).some(Boolean)) {
       return next(new BadRequestError("OAuth users cannot set a password unless unlinked."));
    }

    const isValid = await comparePassword(currentPassword, user.password);
    if (!isValid) {
      return next(new BadRequestError("Incorrect current password"));
    }

    if (newPassword.length < 8) {
      return next(new BadRequestError("New password must be at least 8 characters long"));
    }

    user.password = await hashPassword(newPassword);
    
    // Invalidate sessions (refresh tokens) if needed
    user.refreshTokens = [];
    
    await user.save();

    return sendSuccess(res, 200, "Password updated successfully. Please log in again.");
  } catch (error) {
    next(new InternalServerError(error.message));
  }
};

/**
 * Delete the user account.
 * Requires password confirmation for local users.
 * @param {import('express').Request} req - Express request object.
 * @param {import('express').Response} res - Express response object.
 * @param {import('express').NextFunction} next - Express next middleware function.
 */
export const deleteAccount = async (req, res, next) => {
  try {
    const { password } = req.body;
    const user = await userModel.findById(req.user._id).select("+password");

    if (!user) {
      return next(new AppError("User not found", 404));
    }

    // Require password if user is not purely OAuth
    if (user.password) {
      if (!password) {
        return next(new BadRequestError("Password is required to delete account"));
      }
      const isValid = await comparePassword(password, user.password);
      if (!isValid) {
        return next(new BadRequestError("Incorrect password"));
      }
    }

    // Perform Hard Delete
    await userModel.findByIdAndDelete(user._id);

    // Clear cookies
    res.clearCookie("refreshToken", { path: "/" });

    return sendSuccess(res, 200, "Account deleted successfully");
  } catch (error) {
    next(new InternalServerError(error.message));
  }
};
