const jwt = require("jsonwebtoken");

const User = require("../models/userModel");
const catchAsync = require("../utils/catchAsync"); // For error handling
const AppError = require("../utils/appError"); // Custom error class

// Utility function to verify the JWT token
const verifyToken = (token) => {
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    return decoded;
  } catch (error) {
    return null; // Token is invalid or expired
  }
};

exports.getCurrentUser = catchAsync(async (req, res, next) => {
  let token;

  // 1) Get token from cookie
  if (req.cookies.jwt) {
    token = req.cookies.jwt;
  }

  console.log(token)

  if (!token) {
    return next(
      new AppError("You are not logged in! Please log in to get access.", 401)
    );
  }

  // 2) Verify token
  const decoded = verifyToken(token);

  if (!decoded) {
    return next(
      new AppError("Invalid token. Please log in again to get access.", 401)
    );
  }

  // 3) Check if user still exists
  const currentUser = await User.findById(decoded.id);

  if (!currentUser) {
    return next(
      new AppError(
        "The user belonging to this token does no longer exist.",
        401
      )
    );
  }

  // 4) Check if user changed password after the token was issued
  if (currentUser.changedPasswordAfter(decoded.iat)) {
    return next(
      new AppError("User recently changed password! Please log in again.", 401)
    );
  }

  // 5) GRANT ACCESS TO PROTECTED ROUTE
  res.status(200).json({
    status: "success",
    data: {
      user: currentUser,
    },
  });
});

exports.getAllUsers = async (req, res, next) => {
  try {
    const user = await User.find();
    res.status(200).json({
      status: "success",
      data: { user },
    });
  } catch (error) {
    res.status(400).json({
      status: "fail",
      messade: error,
    });
  }
};
