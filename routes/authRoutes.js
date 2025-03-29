const express = require("express");
const router = express.Router();

// Import controller functions
const { registerUser, loginUser, logoutUser } = require("../controllers/authController");

// Signup Routes
router.post("/signup", registerUser);
router.get("/signup", (req, res) => {
  res.render("signup");
});

// Login Routes
router.post("/login", loginUser);
router.get("/login", (req, res) => {
  res.render("login");
});

// Logout Route
router.get("/logout", logoutUser);

module.exports = router;
