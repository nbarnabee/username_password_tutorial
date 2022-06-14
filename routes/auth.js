const express = require("express");
const router = express.Router();

router.get("/login", function (request, response, next) {
  response.render("login");
});

module.exports = router;
