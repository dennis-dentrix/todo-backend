const express = require("express");
const router = express.Router();
const userController = require("../controllers/userControler");
const authController = require("../controllers/authController");

// Add this route to check authentication status
// router.use(authController.protect); 

// router.get('/status', authController.checkAuthStatus);
router.post("/signup", authController.signup);
router.post("/login", authController.login);
router.get('/logout', authController.logout);
router.post("/forgotPassword", authController.forgotPassword);
router.patch("/resetPassword/:token", authController.resetPassword);
router.route("/").get(userController.getAllUsers);
router.get("/current", authController.getCurrentUser);

router.use(authController.protect);
router.patch('/updateMyPassword', authController.updatePassword);
router.patch(
  '/updateMe',
  userController.updateMe
);
module.exports = router;
