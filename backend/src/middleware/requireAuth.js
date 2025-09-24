import passport from "passport";

const requireAuth = (req, res, next) => {
  console.log("=== Auth Middleware Called ===");
  console.log("Request cookies:", req.cookies);
  passport.authenticate("jwt", { session: false }, (err, userModel, info) => {
    console.log("Passport result - err:", err, "user:", userModel, "info:", info);

    if (err) {
      return next(err);
    }
    if (!userModel) {
      return res.status(401).json({ success: false, message: "Unauthorized: Invalid or expired token.", info: info });
    }
    console.log("User authenticated:", userModel.email);
    req.user = userModel;
    next();
  })(req, res, next);
};

export default requireAuth;
