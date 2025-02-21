const { promisify } = require("util");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");

const AppError = require("../utils/appError");
const User = require("../models/userModel");
const catchAsync = require("../utils/catchAsync");
const cookieParser = require("cookie-parser");
const sendEmailWithOTP = require("../utils/sendEmailWithOtp");


const signToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  });
};

const createSendToken = (user, statusCode, req, res) => {
  const token = signToken(user._id);

  const cookieOptions = {
    expires: new Date(
      Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000
    ),
    httpOnly: true,
    secure: req.secure || req.headers['x-forwarded-proto'] === 'https',
    sameSite: 'none' // Consider 'strict' or 'lax' for better security
  };

  if (process.env.NODE_ENV === 'production') {
    cookieOptions.secure = true; // Ensure secure cookies in production
  }

  res.cookie('jwt', token, cookieOptions);
  // Remove password from output
  user.password = undefined;

  res.status(statusCode).json({
    status: 'success',
    token,
    data: {
      user
    }
  });
};

exports.signup = catchAsync(async (req, res, next) => {
  const newUser = await User.create({
    name: req.body.name,
    email: req.body.email,
    password: req.body.password,
    passwordConfirm: req.body.passwordConfirm,
  });

  // Generate an OTP for email verification
  const otp = Math.floor(100000 + Math.random() * 900000).toString(); // Generates a six-digit number
  const hashedOTP = crypto.createHash('sha256').update(otp).digest('hex'); // Hash the OTP

  newUser.emailToken = hashedOTP; // Store hashed OTP in emailToken field
  newUser.passwordResetOTPExpires = Date.now() + (10 * 60 * 1000); // Set expiration time (10 minutes)
  
  await newUser.save({ validateBeforeSave: false });

  try {
    const emailResponse = await sendEmailWithOTP(newUser, otp); // Send plain OTP to user's email
    console.log('Email Response:', emailResponse);
    res.status(201).json({
      status: 'success',
      message: 'Signup successful! Please check your email for the verification OTP.',
      userId: newUser._id // Include the newUser ID in the response
    });
  } catch (err) {
    console.error('Error sending email:', err);
    return next(new AppError(err.message, 500));
  }
});

// Email Verification Controller - Updated for OTP
exports.verifyEmail = catchAsync(async (req, res, next) => {
  const { otp,  } = req.body; 
  const { userId } = req.params;

  if (!otp || !userId) {
    return next(new AppError("Please provide the OTP and user ID.", 400));
  }

  const hashedOTP = crypto.createHash('sha256').update(otp).digest('hex'); // Hash the provided OTP

  const user = await User.findOne({
    _id: userId,
    emailToken: hashedOTP,
    passwordResetOTPExpires: { $gt: Date.now() }, // Check if the OTP has not expired
  });

  if (!user) {
    return next(new AppError("Invalid or expired OTP.", 401));
  }

  // Update user's verification status
  user.isVerified = true;
  user.emailToken = undefined; // Clear the token after verifying
  user.passwordResetOTPExpires = undefined; // Clear the expiration time
  await user.save({validateBeforeSave: false});

  res.status(200).json({ message: 'Email verified successfully!' });
});

exports.login = catchAsync(async (req, res, next) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return next(new AppError('Please provide email and password!', 400));
  }

  const user = await User.findOne({ email }).select('+password');

  if (!user || !(await user.correctPassword(password, user.password))) {
    return next(new AppError('Incorrect email or password. Try again.', 401));
  }

  createSendToken(user, 200, req, res);
});

exports.getCurrentUser = catchAsync(async (req, res, next) => {
  if (req.cookies.jwt) {
    token = req.cookies.jwt;
  } else {
    return next(new AppError("Not logged in", 401));
  }

  // Verify token
  const decoded = jwt.verify(req.cookies.jwt, process.env.JWT_SECRET);
  
  // Check if user still exists
  const currentUser = await User.findById(decoded.id);
  
  if (!currentUser) {
    return next(new AppError('The user belonging to this token does no longer exist.', 401));
  }

  res.status(200).json({
    status: 'success',
    data: {
      user: currentUser,
    },
  });
});

exports.logout = (req, res) => {
  res.cookie('jwt', 'loggedout', {
    expires: new Date(Date.now() - 10 * 1000),
    httpOnly: true,
    secure: req.secure || req.headers['x-forwarded-proto'] === 'https', // Ensure secure flag is consistent
    sameSite: 'None'
  });
  res.status(200).json({ status: 'success' });
};

exports.protect = catchAsync(async (req, res, next) => {
  // GET THE TOKEN
  let token;
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith("Bearer")
  ) {
    token = req.headers.authorization.split(" ")[1];
  }

  // IF NOT LOGGED IN MEANS NO TOKEN, THEREFORE RETURN ERROR
  if (!token) {
    return next(
      new AppError("You are not logged in! Please login to proceed.", 404)
    );
  }

  // verify the token
  const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

  // CHECK IF USER USER STILL EXIST
  const freshUser = await User.findById(decoded.id);
  if (!freshUser) {
    return next(
      new AppError("The user belongong to this token does not exist.", 401)
    );
  }

  // check if password has been changed after log in
  if (freshUser.changedPasswordAt(decoded.iat)) {
    return next(new AppError("Password has been changed. Login again", 401));
  }

  req.user = freshUser;
  next();
});

exports.forgotPassword = catchAsync(async (req, res, next) => {
  const { email } = req.body;
  
  if (!email) {
    return next(new AppError("Please provide your email",400));
  }

  const user = await User.findOne({ email });

  if (!user) {
    return next(new AppError("There is no user with that email address.",404));
  }

  // Generate a random OTP
  const otp = Math.floor(100000 + Math.random() * 900000).toString(); // Generates a six-digit number

  // Store hashed OTP and expiration time
  const hashedOTP = crypto.createHash('sha256').update(otp).digest('hex');
  
  user.passwordResetOTP = hashedOTP; // Store hashed OTP
  user.passwordResetOTPExpires = Date.now() + (10 * 60 * 1000); // Set expiration time (10 minutes)
  
  await user.save({ validateBeforeSave: false });

  try {
    const emailResponse = await sendEmailWithOTP(user, otp); // Send plain OTP to user's email
    res.status(200).json(emailResponse);
  } catch (err) {
    return next(new AppError(err.message,500));
  }
});

// Reset Password Controller
exports.verifyResetOTP = catchAsync(async (req, res, next) => {
  const { otp } = req.body;

  if (!otp) {
      return next(new AppError("Please provide the OTP.", 400));
  }

  const hashedOTP = crypto.createHash('sha256').update(otp).digest('hex');

  const user = await User.findOne({
      passwordResetOTP: hashedOTP,
      passwordResetOTPExpires: { $gt: Date.now() }, // Check if the OTP has not expired
  });

  if (!user) {
      return next(new AppError("Invalid or expired OTP.", 401));
  }

  // If OTP is valid, send a success response
  res.status(200).json({
      status: 'success',
      message: 'OTP is valid. You can now set your new password.',
      userId: user._id // Optionally send back user ID or any other necessary info
  });
});

exports.resetPassword = catchAsync(async (req, res, next) => {
  const { password, passwordConfirm } = req.body;
  const userId = req.params.userId; // Get user ID from request parameters

  if (!password || !passwordConfirm) {
      return next(new AppError("Please provide both password and password confirmation.", 400));
  }

  // Fetch the user using the provided userId
  const user = await User.findById(userId);

  if (!user) {
      return next(new AppError("User not found.", 404));
  }

  // Set new password and clear the OTP fields
  user.password = password;
  user.passwordConfirm = passwordConfirm;

  // Clear OTP fields after use
  user.passwordResetOTPExpires = undefined; // Assuming you want to clear this
  user.passwordResetOTP = undefined; // Assuming you want to clear this as well

  await user.save();

  createSendToken(user, 200, req, res); // Log in the user and send JWT
});



exports.updatePassword = catchAsync(async (req, res, next) => {
  // 1) Get user from collection
  const user = await User.findById(req.user.id).select('+password');

  // 2) Check if POSTed current password is correct
  if (!(await user.correctPassword(req.body.passwordCurrent, user.password))) {
    return next(new AppError('Your current password is wrong.', 401));
  }

  // 3) If so, update password
  user.password = req.body.password;
  user.passwordConfirm = req.body.passwordConfirm;
  await user.save();

  // 4) Log user in, send JWT
  createSendToken(user, 200, req, res);
});