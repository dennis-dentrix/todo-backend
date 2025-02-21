const express = require("express");
const router = express.Router();
const authController = require("../controllers/authController");
const userController = require("../controllers/userControler");


// Remove emailToken from URL and change to POST
router.post("/signup", authController.signup);
router.post("/verifyEmail", authController.verifyEmail); // Changed to POST
router.post("/login", authController.login);
router.get("/logout", authController.logout);
router.post("/forgotPassword", authController.forgotPassword);
router.post('/verifyResetOTP', authController.verifyResetOTP);
router.patch("/resetPassword/:userId", authController.resetPassword); 
router.route("/").get(userController.getAllUsers);
router.get("/current", authController.getCurrentUser);

// Protect routes after this point
router.use(authController.protect);
router.patch("/updateMyPassword", authController.updatePassword);
router.patch("/updateMe", userController.updateMe);

module.exports = router;
