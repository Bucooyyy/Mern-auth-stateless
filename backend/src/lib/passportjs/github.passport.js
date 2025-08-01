import passport from "passport";
import GithubStrategy from "passport-github2";
import user from "../../models/user.model.js";
import { refreshToken } from "../tokenjwt.js";
passport.use(
  new GithubStrategy(
    {
      clientID: process.env.GITHUB_CLIENT_ID,
      clientSecret: process.env.GITHUB_SECRET,
      callbackURL: "/api/auth/github/callback",
    },
    async (accessToken, refreshToken, profile, done) => {
      const User = await user.findOneAndUpdate(
        { "oauth.githubId": profile.id },
        { name: profile.username, email: profile.emails[0].value, "oauth.githubId": profile.id, isAccountVerified: true },
        { upsert: true, new: true }
      );
      done(null, User);
    }
  )
);

// update token jika perlu
