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
      scope: ["user:email"], // Request email scope
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        // validate email
        const email = profile.emails?.[0]?.value || `${profile.username}@github.com`;

        const User = await user.findOneAndUpdate(
          { "oauth.githubId": profile.id },
          { name: profile.username, email: email, "oauth.githubId": profile.id, isAccountVerified: true },
          { upsert: true, new: true }
        );
        done(null, User);
      } catch (error) {
        console.error("Github Strategy Error:", error);
        done(error, null);
      }
    }
  )
);

// update token jika perlu
