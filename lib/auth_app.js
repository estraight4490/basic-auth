"use strict";

require("dotenv").config();

const express = require("express");
const app = express();
const jwt = require("jsonwebtoken");

// Allow app to parse json data in a POST request object
app.use(express.json());

let refresh_tokens = [];

app.post("/token", (req, res) => {
  const refresh_token = req.body.token;
  console.log(refresh_token);
  if (refresh_token === null) return res.sendStatus(401);
  if (!refresh_tokens.includes(refresh_token)) return res.sendStatus(403);
  jwt.verify(refresh_token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    const access_token = generate_access_token({ name: user.name });
    res.json({ access_token });
  });
});

app.delete("/logout", (req, res) => {
  refresh_tokens = refresh_tokens.filter(token => token !== req.body.token);
  res.sendStatus(204);
});

app.post("/login_test", (req, res) => {

  // TODO: Username needs to be authenticated correctly (just grabbing it now for testing and demoing purposes)
  const username = req.body.username;
  const user = { name: username };

  const accessToken = generate_access_token(user);
  const refreshToken = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET);
  refresh_tokens.push(refreshToken);
  res.json({ accessToken, refreshToken });
});

function generate_access_token(user) {
  return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "15s" });
}

module.exports = app;
