import passport from "passport";
import GoogleStrategy from "passport-google-oauth20";
import user from "../../models/user.model.js";
import { refreshToken } from "../tokenjwt.js";

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_SECRET,
      callbackURL: "/api/auth/google/callback",
    },
    async (accessToken, refreshToken, profile, done) => {
      const User = await user.findOneAndUpdate(
        { "oauth.googleId": profile.id },
        { name: profile.displayName, email: profile.emails[0].value, "oauth.googleId": profile.id, isAccountVerified: true },
        { upsert: true, new: true }
      );
      done(null, User);
    }
  )
);

// apabila reset token diperlukan akan diupdate
