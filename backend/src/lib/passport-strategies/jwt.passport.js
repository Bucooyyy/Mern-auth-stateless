import { Strategy as JwtStrategy, ExtractJwt } from "passport-jwt";
import passport from "passport";
import user from "../../models/user.model.js";

const opts = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: process.env.JWT_SECRET,
};
passport.use(
  "jwt",
  new JwtStrategy(opts, async (jwt_payload, done) => {
    try {
      const User = await user.findById(jwt_payload.id).select("-password");
      if (User) {
        return done(null, User);
      } else {
        return done(null, false);
      }
    } catch (error) {
      console.error("JWT Strategy Error:", error);
      return done(error, false);
    }
  })
);
