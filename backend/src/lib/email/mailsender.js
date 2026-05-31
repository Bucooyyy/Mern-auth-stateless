import transporter from "./nodemailer.config.js";

const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:5173";

export const sendVerificationEmail = async (email, token) => {
  const mailOptions = {
    from: `"V.ME Auth" <${process.env.EMAIL_USER}>`,
    to: email,
    subject: "Verify Your Email - V.ME",
    html: `
      <h2>Welcome to V.ME!</h2>
      <p>Please verify your email address by clicking the link below:</p>
      <a href="${FRONTEND_URL}/verify-email?token=${token}">Verify Email</a>
      <p>This link will expire in 24 hours.</p>
    `,
  };
  await transporter.sendMail(mailOptions);
};

export const sendEmailVerifyPasswordReset = async (email, token) => {
  const mailOptions = {
    from: `"V.ME Auth" <${process.env.EMAIL_USER}>`,
    to: email,
    subject: "Password Reset Request - V.ME",
    html: `
      <h2>Password Reset</h2>
      <p>You requested a password reset. Click the link below to set a new password:</p>
      <a href="${FRONTEND_URL}/reset-password?token=${token}">Reset Password</a>
      <p>This link will expire in 15 minutes. If you did not request this, please ignore this email.</p>
    `,
  };
  await transporter.sendMail(mailOptions);
};
