const express = require("express");
const passport = require("passport");
const LocalStrategy = require("passport-local");
const crypto = require("crypto");
const db = require("../db");

// the above is the db.js file, which is very neat

const router = express.Router();

passport.use(
  new LocalStrategy(function verify(username, password, cb) {
    db.get(
      "SELECT * FROM users WHERE username = ?",
      [username],
      function (err, row) {
        if (err) {
          return cb(err);
        }
        if (!row) {
          return cb(null, false, {
            message: "Incorrect username or password.",
          });
        }
        crypto.pbkdf2(
          password,
          row.salt,
          310000,
          32,
          "sha256",
          function (err, hashedPassword) {
            if (err) {
              return cb(err);
            }
            if (!crypto.timingSafeEqual(row.hashed_password, hashedPassword)) {
              return cb(null, false, {
                message: "Incorrect username or password.",
              });
            }
            return cb(null, row);
          }
        );
      }
    );
  })
);

// the above configures the LocalStrategy to fetch the user record from the app's database and verify the hashed password that is stored with the record.  If that succeeds, the password is valid and the user is authenticated.

passport.serializeUser(function (user, cb) {
  process.nextTick(function () {
    cb(null, { id: user.id, username: user.username });
  });
});

passport.deserializeUser(function (user, cb) {
  process.nextTick(function () {
    return cb(null, user);
  });
});

// the above configures Passport to manage the login session

router.get("/login", function (request, response, next) {
  response.render("login");
});

router.post(
  "/login/password",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/login",
  })
);

// so when someone clicks the "sign in" button, that makes a post request to "/login/password"; the server's response is to run the authentication function.
// if authentication succeeds, the user is redirected to the index page; on failure, directed back to the login screen

router.post("/logout", function (request, response, next) {
  request.logout(function (err) {
    if (err) {
      return next(err);
    }
    response.redirect("/");
  });
});

// clicking the "logout" button makes a POST request to "/logout"; this route hears that and, unless there's an error, redirects the user to the root page.  but to be honest it is unclear to me how the actual logout is happening.

router.get("/signup", function (request, response, next) {
  response.render("signup");
});

// a simple route that returns the rendered signup page

router.post("/signup", function (request, response, next) {
  var salt = crypto.randomBytes(16);
  crypto.pbkdf2(
    request.body.password,
    salt,
    310000,
    32,
    "sha256",
    function (err, hashedPassword) {
      if (err) {
        return next(err);
      }
      db.run(
        "INSERT INTO users (username, hashed_password, salt) VALUES (?, ?, ?)",
        [request.body.username, hashedPassword, salt],
        function (err) {
          if (err) {
            return next(err);
          }
          var user = {
            id: this.lastID,
            username: request.body.username,
          };
          request.login(user, function (err) {
            if (err) {
              return next(err);
            }
            response.redirect("/");
          });
        }
      );
    }
  );
});

// a route that handles a POST request made to "/signup" (i.e., new user registration)
// while I don't understand the fine details, it's clear enough what is happening:  the password is salted and hashed according to a particular scheme, and then the user information is inserted into the database as an array containing the username (as entered into the form), the hashed password, and the salt
// then the user is automatically logged in and redirected to the index

module.exports = router;
