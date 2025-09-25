import speakeasy from "speakeasy";
import qrcode from "qrcode";

export const verifyingMFA = (user, token) => {
  return speakeasy.totp.verify({
    secret: user.MFA.secret || user.MFA.tempSecret,
    encoding: "base32",
    token: token,
  });
};
