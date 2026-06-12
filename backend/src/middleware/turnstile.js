import axios from 'axios';

/**
 * Middleware to verify the Cloudflare Turnstile token.
 * Prevents automated bots from accessing authentication endpoints.
 * @param {Object} req - The Express request object.
 * @param {Object} res - The Express response object.
 * @param {Function} next - The next middleware function.
 */
export const verifyTurnstile = async (req, res, next) => {
  const token = req.body['cf-turnstile-response'];
  const secretKey = process.env.TURNSTILE_SECRET_KEY;

  if (!token) {
    return res.status(400).json({ success: false, message: "Turnstile token is required." });
  }

  try {
    const response = await axios.post('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      secret: secretKey,
      response: token,
      remoteip: req.ip
    });

    if (response.data.success) {
      return next();
    } else {
      return res.status(403).json({ success: false, message: "Bot verification failed." });
    }
  } catch (error) {
    return res.status(500).json({ success: false, message: "Turnstile verification error." });
  }
};
