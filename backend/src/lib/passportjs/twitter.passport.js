import passport from "passport";
import TwitterStrategy from "passport-twitter";
import user from "../../models/user.model.js";
import { refreshToken } from "../tokenjwt.js";

passport.use(
  new TwitterStrategy(
    {
      clientID: process.env.TWITTER_CONSUMER_KEY,
      clientSecret: process.env.TWITTER_CONSUMER_SECRET,
      callbackURL: "/api/auth/twitter/callback",
      includeEmail: true, // Ensure email is included in the profile
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        // validate email
        const email = profile.emails?.[0]?.value || `${profile.username}@twitter.com`;

        const User = await user.findOneAndUpdate(
          { "oauth.twitterId": profile.id },
          { name: profile.username, email: email, "oauth.twitterId": profile.id, isAccountVerified: true },
          { upsert: true, new: true }
        );
        done(null, User);
      } catch (error) {
        console.error("Twitter Strategy Error:", error);
        done(error, null);
      }
    }
  )
);

// akan menggunakan refreshToken jika diperlukan
