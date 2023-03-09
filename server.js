const fs = require("fs");
const https = require("https");
const path = require("path");
const helmet = require("helmet");
const express = require("express");
const cookies = require("cookie-session");
const passport = require("passport");
const { Strategy } = require("passport-google-oauth20");
require("dotenv").config();

const PORT = 3000;

const config = {
  CLIENT_ID: process.env.CLIENT_ID,
  CLIENT_SECRET: process.env.CLIENT_SECRET,
  CLIENT_COOKIE_1: process.env.CLIENT_COOKIE_1,
  CLIENT_COOKIE_2: process.env.CLIENT_COOKIE_2,
};

const AUTH_OPTIONS = {
  callbackURL: "/auth/google/callback",
  clientID: config.CLIENT_ID,
  clientSecret: config.CLIENT_SECRET,
};

function verfiyCallback(accessToken, refreshToken, profile, done) {
  console.log("Google profile", profile);
  done(null, profile);
}

passport.use(new Strategy(AUTH_OPTIONS, verfiyCallback));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  done(null, id);
});

const app = express();

app.use(helmet());

app.use(
  cookies({
    name: "My session",
    maxAge: 24 * 60 * 60 * 1000,
    keys: [config.CLIENT_COOKIE_1, config.CLIENT_COOKIE_2],
  })
);
//app.use(passport.initialize());
app.use(passport.session());

function checkLoggedIn(req, res, next) {
  console.log("Current user is:", req.user);
  const isLoggedIn = req.isAuthenticated() && req.user;

  if (!isLoggedIn) {
    return res.status(401).json({
      error: "You must be logged in",
    });
  }

  next();
}

app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["email"],
  })
);

app.get(
  "/auth/google/callback",
  passport.authenticate("google", {
    failureRedirect: "/failure",
    successRedirect: "/",
    session: true,
  }),
  (req, res) => {
    console.log("Google called us back!");
  }
);

app.get("/auth/logout", (req, res) => {
  req.logOut();
  return res.redirect("/");
});

app.get("/secret", checkLoggedIn, (req, res) => {
  return res.send("Your personal secret value is 42");
});

app.get("/failure", (req, res) => {
  return res.send("Authentication failed");
});

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

https
  .createServer(
    {
      key: fs.readFileSync("key.pem"),
      cert: fs.readFileSync("cert.pm"),
    },
    app
  )
  .listen(PORT, () => {
    console.log(`Listening to port ${PORT}`);
  });
