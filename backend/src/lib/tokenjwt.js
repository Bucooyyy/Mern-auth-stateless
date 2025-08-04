import jwt from "jsonwebtoken";

export const generateToken = (res, userId) => {
  const accessToken = jwt.sign({ userId, type: "access" }, process.env.JWT_SECRET, { expiresIn: "15m" });

  res.cookie("token", accessToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: 15 * 60 * 1000, // 15 menit
  });

  const refreshToken = jwt.sign({ userId, type: "refresh" }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: "90d" });

  res.cookie("token", refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: 90 * 24 * 60 * 60 * 1000, // 90 hari
  });
  return { accessToken, refreshToken };
};

export const blackListToken = (token) => {};
