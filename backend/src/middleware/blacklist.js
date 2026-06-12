import redisClient from '../config/redis.config.js';

/**
 * Middleware to check if the provided JWT is blacklisted in Redis.
 * If the token is found in the blacklist, access is denied.
 * @param {Object} req - The Express request object.
 * @param {Object} res - The Express response object.
 * @param {Function} next - The next middleware function.
 */
export const checkBlacklist = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return next(); // Let the authentication middleware handle missing tokens

    const isBlacklisted = await redisClient.get(`bl_${token}`);
    if (isBlacklisted) {
      return res.status(401).json({ success: false, message: "Token has been revoked. Please log in again." });
    }
    next();
  } catch (error) {
    next(error);
  }
};
