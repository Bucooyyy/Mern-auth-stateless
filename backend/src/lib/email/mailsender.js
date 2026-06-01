import getTransporter from "../../config/nodemailer.config.js";
import logger from "../../config/winston.logger.js";

const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:5173";

const send = async (to, subject, html) => {
  try {
    const transport = await getTransporter();
    const info = await transport.sendMail({ from: process.env.EMAIL_USER, to, subject, html });
    logger.info("Email sent", { to, subject, messageId: info.messageId });
    return info;
  } catch (err) {
    // Never crash the request because of an email failure; log and continue.
    logger.error("Email send failed", { to, subject, error: err.message });
  }
};

export const sendVerificationEmail = async (email, token) => {
  const url = `${FRONTEND_URL}/verify-email?token=${token}`;
  return send(
    email,
    "Verify your email address",
    `
      <h2>Welcome!</h2>
      <p>Please verify your email by clicking the link below. It expires in 24 hours.</p>
      <a href="${url}">${url}</a>
    `,
  );
};

export const sendEmailVerifyPasswordReset = async (email, token) => {
  const url = `${FRONTEND_URL}/reset-password?token=${token}`;
  return send(
    email,
    "Password Reset Request - V.ME",
    `
      <h2>Password Reset</h2>
      <p>Click the link below to reset your password. The link expires in 1 hour.</p>
      <a href="${url}">${url}</a>
      <p>If you did not request this, please ignore this email.</p>
    `,
  );
};

export const sendMFASetupEmail = async (email) => {
  return send(
    email,
    "MFA enabled on your account",
    `
      <h2>Multi-Factor Authentication Enabled</h2>
      <p>MFA has been successfully enabled on your account.</p>
      <p>If you did not do this, please contact support immediately.</p>
    `,
  );
};
