const { promisify } = require("util");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");

const AppError = require("../utils/appError");
const User = require("../models/userModel");
const catchAsync = require("../utils/catchAsync");
const cookieParser = require("cookie-parser");
const sendEmailWithToken = require("../utils/sendEmailWithToken");

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

// authController.js
exports.signup = catchAsync(async (req, res, next) => {
  const newUser = await User.create({
    name: req.body.name,
    email: req.body.email,
    password: req.body.password,
    passwordConfirm: req.body.passwordConfirm,
  });

  // Generate email verification token and link
  const verificationToken = newUser.createEmailVerificationToken();
  await newUser.save({ validateBeforeSave: false });

  createSendToken(newUser, 201, req, res);

  // console.log('Verification Token:', verificationToken); 

  // try {
  //   const emailResponse = await sendEmailWithToken(newUser, verificationToken, req, "emailVerification");
  //   console.log('Email Response:', emailResponse); 
  //   res.status(201).json(emailResponse);
  // } catch (err) {
  //   console.error('Error sending email:', err);
  //   return next(new AppError(err.message, 500));
  // }
});
exports.verifyEmail = catchAsync(async (req, res, next) => {
  const { emailToken } = req.params;

  // Hash the token from the URL
  const hashedToken = crypto
    .createHash('sha256')
    .update(emailToken)
    .digest('hex');

  console.log('Hashed Token:', hashedToken); // Debugging log

  const user = await User.findOne({ emailToken: hashedToken });

  if (!user) {
    console.error('Invalid or expired token'); // Debugging log
    return next(new AppError('Invalid or expired token.', 400));
  }

  // Update user's verification status
  user.isVerified = true;
  user.emailToken = undefined; // Clear the token after verifying
  await user.save({ validateBeforeSave: false });

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
  // 1. Check if the email is valid
  const { email } = req.body;
  if (!email) {
    return next(new AppError("Please provide your email", 400));
  }

  // 2. Check if the user exists
  const user = await User.findOne({ email });

  if (!user) {
    return next(new AppError("There is no user with that email address.", 404));
  }

  // 3. Generate a random reset token
  const resetToken = crypto.randomBytes(32).toString("hex");
  const hashedToken = crypto.createHash("sha256").update(resetToken).digest("hex");

  // Set token expiration time (e.g., 10 minutes from now)
  user.passwordResetToken = hashedToken;
  user.passwordResetExpires = Date.now() + 24 * 60 * 1000; // 10 minutes

  // Save the user document without validation
  await user.save({ validateBeforeSave: false });

  try {
    const emailResponse = await sendEmailWithToken(user, resetToken, req, "passwordReset");
    res.status(200).json(emailResponse);
  } catch (err) {
    return next(new AppError(err.message, 500));
  }
});

exports.resetPassword = catchAsync(async (req, res, next) => {
  // GET USER BASED ON THE TOKEN
  const hashedToken = crypto
    .createHash("sha256")
    .update(req.params.token)
    .digest("hex");

  const user = await User.findOne({
    passwordResetToken: hashedToken,
    passwordResetExpires: { $gt: Date.now() },
  });

  if (!user)
    return next(new AppError("The token is invalid or does not exist.", 401));
  // SET NEW PASSWORD IF THE TOKEN HAS NOT EXPIRED AND THERE IS A USER
  user.password = req.body.password;
  user.passwordConfirm = req.body.passwordConfirm;
  user.passwordResetExpires = undefined;
  user.passwordResetToken = undefined;

  // UPDATE CHANGEDPASSWORDAT PROPERTY
  await user.save();

  // LOG USER IN, SEND JWT
  createSendToken(user, 200, req, res);
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