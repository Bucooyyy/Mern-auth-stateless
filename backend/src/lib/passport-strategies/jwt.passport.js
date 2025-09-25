import { Strategy as JwtStrategy, ExtractJwt } from "passport-jwt";
import passport from "passport";
import user from "../../models/user.model.js";

const cookieExtractor = (req) => {
  try {
    console.log("cookies received:", req.cookies);

    let token = null;
    if (req && req.cookies) {
      token = req.cookies.accessToken;
    }
    console.log("Extracted token:", token);
    return token;
  } catch (error) {
    console.error("Error extracting token from cookies", error);
  }
};

const opts = {
  jwtFromRequest: cookieExtractor,
  secretOrKey: process.env.JWT_SECRET,
  // passReqToCallback: true,
};

passport.use(
  "jwt",
  new JwtStrategy(opts, async (jwt_payload, done) => {
    console.log("JWT Payload:", jwt_payload); // Debug log
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

export default passport;
