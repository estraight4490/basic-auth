"use strict";

require("dotenv").config();

const express = require("express");
const app = express();
const base64url = require("base64-url");
const bodyParser = require("body-parser");
const path = require("path");
const Crypto = require("crypto");
const jwt = require("jsonwebtoken");
const { promisify } = require("util");
const pbkdf2 = promisify(Crypto.pbkdf2);

// Point the view directory to views
app.set("views", path.join(__dirname, "..", "views"));
// Set the view engine to ejs
app.set("view engine", "ejs");
// Allow app to parse form data in a POST request
app.use(bodyParser.urlencoded({ extended: true }));
// Allow app to parse json data in a POST request object
app.use(express.json());

// When a user creates an account, store the data here. (This will become a db in the future)
const user_info = [];

// 404 Handler. Render this page in the case of a 404.
function not_found(req, res) {
  res.status(404).render("404");
}
app.get("/", (req, res) => {
  res.status(200).render("home");
});

app.get("/register", (req, res) => {
  res.status(200).send("This will be the user registration page");
});

app.post("/register", async (req, res) => {
  const email = req.body.email;
  const username = req.body.username;
  const password = req.body.password;
  // TODO: validate with passport
  // TODO: if validated, create a hash, salt, rounds and store all that plus hashed password and username in local array
  const salt = await Crypto.randomBytes(128).toString("base64");
  const rounds = 10000; // TODO: Move this to a config value
  const hash = await pbkdf2(password, salt, rounds, 64, "sha512");
  // Returns 0 if buffers are equal
  const comparison = Buffer.compare(hash, await pbkdf2(password, salt, rounds, 64, "sha512"));

  if(comparison === 0) {
    console.log("password match");
  }
  else {
    console.log("password does not match");
  }

  user_info.push({
    email,
    username,
    password_hash: hash,
    salt,
    rounds,
  });

  sign(salt, "1", email, hash);

  res.status(200).send(`The password for ${username} is ${password}`);
});

app.get("/login", (req, res) => {
  // TODO: Authenticate user login and return JWT authorization
  // 1. Receive user submitted login details
  // 2. Using passport, validate input
  // 3. If user exists in db, create JWT authorization
  // 4. JWT will be created with bare minimume secret and HMA
  // Tips: use nodes build in crypto module (crypto.Hmac)
  // Use your new Hmac object and update: i.e. Hmac.update(user_id)
  // Finish with Hmac.digest("base64")
  res.status(200).send("This will be the login page");
});

app.post("/login", async (req, res) => {
  const username = req.body.username;
  const password = req.body.password;
  // TODO: Logging in a user
  // When a user submits their credentials, first look for their email
  // If email doesn't exist, return a login error message
  // If email exists, hash the user submitted password and compare to stored hashed password
  // If the two hash buffers match, the user can login
  // Create a token using jwt (research npm package for this)
  // Send the users id, email and name along with the token
  // On the client side, the token will be saved in a secure cookie
  // When the user hits a restricted route that requires authorization,
  // it will get the token from the cookie and pass it back to the server in a header
  // Back on the server, get the token from the header, authenticate it then move forward


  res.status(200).send("This is the POST to authenticate user login");
});

const posts = [
  {
    username: "Erik",
    title: "Post 1"
  },
  {
    username: "Nozomi",
    title: "Post 2"
  }
];

app.get("/posts", authenticate_token, (req, res) => {
  res.json(posts.filter(post => post.username === req.user.name));
});

app.post("/login_test", (req, res) => {

  // TODO: Username needs to be authenticated correctly (just grabbing it now for testing and demoing purposes)
  const username = req.body.username;
  const user = { name: username };

  const accessToken = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET);
  res.json({ accessToken });
});

app.use(not_found);

// Optional way to sign a token (return this and send as the token)
// THIS WILL BE THE AUTH TOKEN
// Generate the signature with id, email, and hashed password
// Pass to browser to be saved in a cookie along with the id, email and hashed password
// When a user tries to access a restricted route, the same creds will be sent in headers
// Recreate the signature with the id, email and pwd and match the output to the sent token
// Authorized if the two tokens match
function sign(salt, id, email, hashed_password) {
  const hmac = Crypto.createHmac("sha256", salt);
  hmac.update(id);
  hmac.update(email);
  hmac.update(hashed_password);

  const digested = hmac.digest("base64");
  const escaped = base64url.escape(digested);
  console.log(escaped);
  return escaped;
}

function authenticate_token(req, res, next) {
  // TODO: Parse authentication header
  // Remember: The header will be "Bearer <token>". Split at the space and get the second array entry
  const auth_header = req.headers["authorization"];
  // Check if auth_header isn't null.
  const token = auth_header && auth_header.split(" ")[1];
  if (token === null) return res.sendStatus(401);

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);

    req.user = user;
    next();
  });

}

module.exports = app;
