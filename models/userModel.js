const crypto = require("crypto");
const mongoose = require("mongoose");
const validator = require("validator");
const bcrypt = require("bcryptjs");
const { type } = require("os");

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, "A user must have a name"],
  },
  email: {
    type: String,
    required: [true, "A user must have an email"],
    lowercase: true,
    unique: true,
    validate: [validator.isEmail, "Please provide a valid email"],
  },
  photo: String,
  password: {
    type: String,
    required: [true, "Kindly provide a password"],
    select: false,
    minlength: 8,
  },
  passwordConfirm: {
    type: String,
    required: [true, "Confirm your password"],
    validate: {
      validator: function (el) {
        return el === this.password;
      },
      message: "Passwords do not match",
    },
  },
  isVerified: { type: Boolean, default: false },
  emailToken: { type: String },
  passwordChangedAt: Date,

  // New fields for OTP implementation:
  passwordResetOTP: {
    type: String,
    select: false, // Important:  Don't return this in query results by default
  },
  passwordResetOTPExpires: {
    type: Date,
    select: false, // Important:  Don't return this in query results by default
  },
});

userSchema.pre("save", async function (next) {
  try {
    if (!this.isModified("password")) return next();

    this.password = await bcrypt.hash(this.password, 12);
    this.passwordConfirm = undefined;

    next();
  } catch (err) {
    next(err);
  }
});

userSchema.methods.correctPassword = async function (candidatePSWD, userPSWD) {
  return await bcrypt.compare(candidatePSWD, userPSWD);
};

userSchema.methods.changedPasswordAt = function (JWTtimestamp) {
  if (this.passwordChangedAt) {
    const changedTimeStamp = this.passwordChangedAt.getTime() / 1000;
    return JWTtimestamp < changedTimeStamp;
  }
  return false;
};

const User = mongoose.model("User", userSchema);

module.exports = User;
