const crypto = require("crypto");
const mongoose = require("mongoose");
const validator = require("validator");
const bcrypt = require("bcryptjs");

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
      // This only works on CREATE and SAVE!!!
      validator: function (el) {
        return el === this.password;
      },
      message: "Passwords do not match",
    },
  },
  isVerified: { type: Boolean, default: false }, // New field for email verification
  emailToken: { type: String }, // New field for storing verification token
  passwordChangedAt: Date,
  passwordResetToken: String,
  passwordResetExpires: Date,
});

// Middleware to hash password before saving
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

// Method to compare passwords
userSchema.methods.correctPassword = async function (candidatePSWD, userPSWD) {
  return await bcrypt.compare(candidatePSWD, userPSWD);
};

// Method to check if password has changed
userSchema.methods.changedPasswordAt = function (JWTtimestamp) {
  if (this.passwordChangedAt) {
    const changedTimeStamp = this.passwordChangedAt.getTime() / 1000;
    return JWTtimestamp < changedTimeStamp;
  }
  return false;
};

// Method to create a password reset token
userSchema.methods.createPasswordResetToken = function() {
  const resetToken = crypto.randomBytes(32).toString('hex');

  this.passwordResetToken = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');

  // console.log({ resetToken }, this.passwordResetToken);

  this.passwordResetExpires = Date.now() + 10 * 60 * 1000;

  return resetToken;
};

// Method to generate email verification token
userSchema.methods.createEmailVerificationToken = function () {
  const emailToken = crypto.randomBytes(32).toString('hex');
  
  this.emailToken = crypto.createHash('sha256').update(emailToken).digest('hex');
  
  return emailToken; 
};

const User = mongoose.model("User", userSchema);

module.exports = User;
