import speakeasy from "speakeasy";

const verifyMFA = (req, res, next) => {
  const { user } = req;
  const token = req.headers["x-mfa-token"];

  if (!user.isMFAEnabled.enabled) {
    return next();
  }

  if (!token) {
    return res.status(401).json({
      message: "MFA token is required.",
      MFARequired: true,
    });
  }

  const verified = speakeasy.totp.verify({
    secret: user.MFA.secret,
    encoding: "base32",
    token: token,
  });

  if (!isVerified) {
    return res.status(401).json({
      message: "Invalid MFA token.",
      MFARequired: true,
    });
  }

  next();
};

export default verifyMFA;
