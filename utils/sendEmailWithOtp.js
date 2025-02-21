const { default: sendEmail } = require("./emails");

const sendEmailWithOTP = async (user, otp) => {
  // We don't need a URL since we are sending an OTP directly
  const subject = "Your Password Reset OTP (Valid for 10 minutes)";
  const message = `
    <p>You requested a password reset. Your OTP is:</p>
    <h2>${otp}</h2>
    <p>This OTP is valid for 10 minutes. If you didn't request this, please ignore this email.</p>
  `;

  try {
    await sendEmail({
      email: user.email,
      name: user.name,
      subject,
      message,
    });

    return {
      status: "success",
      message: "An OTP has been sent to your email address. Please check your inbox.",
    };
  } catch (err) {
    // Cleanup if email fails to send
    user.passwordResetOTP = undefined; // Clear any previous OTP
    user.passwordResetOTPExpires = undefined; // Clear expiry time
    await user.save({ validateBeforeSave: false });

    throw new Error("There was an error sending the email. Please try again later!");
  }
};

module.exports = sendEmailWithOTP;
