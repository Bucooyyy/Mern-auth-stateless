import { isTokenBlacklisted } from "../utils/tokenjwt";
import jwt from "jsonwebtoken";
const authenticateToken = async (req, res, next) => {
  //   const { accessToken, refreshToken } = req.cookies;
  const token = req.cookies.accessToken;

  if (!token) {
    return res.status(401).json({ success: false, message: "Access token required" });
  }

  try {
    const isBlackListed = await isTokenBlacklisted(token);

    if (isBlackListed) {
      return res.status(403).json({ message: "Token has been revoked" });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    res.status(200).json({ success: true, message: "Token is valid", user: decoded });
    next();
  } catch (error) {
    return res.status(403).json({ success: false, message: "Invalid or expired token", error: error.message });
  }
};
