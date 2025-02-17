const express = require("express");
const router = express.Router();
const userController = require("../controllers/userControler");
const authController = require("../controllers/authController");

// Add this route to check authentication status

router.get('/status', authController.checkAuthStatus);

router.post("/signup", authController.signup);
router.post("/login", authController.login);
router.get('/logout', authController.logout);

router.post("/forgotPassword", authController.forgotPassword);
router.patch("/resetPassword/:token", authController.resetPassword);
router.patch('/updateMyPassword', authController.updatePassword);

router.route("/").get(userController.getAllUsers);
router.get("/current", authController.getCurrentUser)
module.exports = router;
