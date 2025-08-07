import passport from "passport";
import DiscordStrategy from "passport-discord";
import user from "../../models/user.model.js";
import { refreshToken } from "../tokenjwt.js";

passport.use(
  new DiscordStrategy(
    {
      clientID: process.env.DISCORD_CLIENT_ID,
      clientSecret: process.env.DISCORD_SECRET,
      callbackURL: "/api/auth/discord/callback",
      scope: ["identify", "email"], // Request identify and email scopes
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const User = await user.findOneAndUpdate(
          { "oauth.discordId": profile.id },
          { name: profile.username, email: profile.emails[0].value, "oauth.discordId": profile.id, isAccountVerified: true },
          { upsert: true, new: true }
        );
        done(null, User);
      } catch (error) {
        console.error("Discord Strategy Error:", error);
        done(error, null);
      }
    }
  )
);
