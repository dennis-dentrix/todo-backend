const { promisify } = require("util");
const crypto = require("crypto");

const AppError = require("../utils/appError");
const User = require("../models/userModel");
const jwt = require("jsonwebtoken");
const catchAsync = require("../utils/catchAsync");
const sendEmail = require("../utils/emails");

const signToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  });
};

const createTokenAndSend = (user, statusCode, res) => {
  const token = signToken(user._id);

  res.status(statusCode).json({
    status: "success",
    token,
    data: {
      user,
    },
  });
};

exports.signup = catchAsync(async (req, res, next) => {
  const newUser = await User.create({
    name: req.body.name,
    email: req.body.email,
    password: req.body.password,
    passwordConfirm: req.body.passwordConfirm,
  });
  // console.log(req.body)
  createTokenAndSend(newUser, 200, res);
});

exports.login = catchAsync(async (req, res, next) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return next(new AppError("Please provide email and password!", 401));
  }

  const user = await User.findOne({ email }).select("+password");

  if (!user || !(await user.correctPassword(password, user.password))) {
    return next(new AppError("Incorrect email or password. Try again.", 401));
  }

  createTokenAndSend(user, 200, res);
});

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
  // console.log(freshUser)

  if (!freshUser) {
    return next(
      new AppError("The user belongong to this token does not exist.", 401)
    );
  }

  // check if password has been changed after log in
  if (freshUser.changedPasswordAt(decoded.iat)) {
    return next(new AppError("Password has been chnaged. Login again", 401));
  }

  req.user = freshUser;
  next();
});

exports.forgotPassword = catchAsync(async (req, res, next) => {
  // CHECK IF THE USER EXISTS
  const user = await User.findOne({
    email: req.body.email,
  });

  if (!user) {
    return next(new AppError("Email not valid for any user. Try again!"), 404);
  }

  // GENERATE RANDOM RESET TOKEN
  const resetToken = user.createPasswordResetToken();
  await user.save({ validateBeforeSave: false });

  // SEND RESET TOKEN TO USER'S EMAIL
  const resetUrl = `${req.protocol}//${req.get(
    "host"
  )}/api/v1/users/resetPassword/${resetToken}`;

  const message = `Forgot your password? Submit a PATCH request with you new password and passwordConfirm to: ${resetUrl}.\nIf you didn't  forget your password then ignore this email`;

  try {
    await sendEmail({
      email: user.email,
      subject: "Your password reste token(valid for 10 mins",
      message,
    });

    res.status(200).json({
      status: "Success",
      message: "Token sent to email.",
    });
  } catch (error) {
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save({ validateBeforeSave: false });

    return next(
      new AppError(
        "There was an error sending the email. Try again later!",
        500
      )
    );
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
  // console.log(user);

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
  createTokenAndSend(user, 200, res);
});
