import jwt from "jsonwebtoken";
import { isTokenBlacklisted } from "../utils/tokenjwt.js";
import { AppError, UnauthorizedError } from "../errors/error.js";
import userModel from "../models/user.model.js";

/**
 * Middleware to authenticate user via JWT from Authorization header.
 * Decodes the token, checks if it's blacklisted, and attaches user to req.user.
 * Use this as an alternative or in parallel to Passport JWT auth.
 * @param {import('express').Request} req - Express request object.
 * @param {import('express').Response} res - Express response object.
 * @param {import('express').NextFunction} next - Express next middleware function.
 */
const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return next(new UnauthorizedError("Access token required in Authorization header"));
    }

    const token = authHeader.split(" ")[1];

    const isBlackListed = await isTokenBlacklisted(token);
    if (isBlackListed) {
      return next(new UnauthorizedError("Token has been revoked"));
    }

    const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET);
    
    // Fetch user to attach to request
    const user = await userModel.findById(decoded.userId).select("-password -MFA.secret -MFA.tempSecret");
    if (!user) {
      return next(new UnauthorizedError("User associated with token not found"));
    }

    // Pass the token along in case needed for further checks
    req.token = token;
    req.user = user;
    next();
  } catch (error) {
    if (error.name === "TokenExpiredError") {
      return next(new UnauthorizedError("Token expired"));
    }
    return next(new UnauthorizedError("Invalid or expired token"));
  }
};

export default authenticateToken;
