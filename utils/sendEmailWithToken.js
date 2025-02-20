const { default: sendEmail } = require("./emails");

const sendEmailWithToken = async (user, token, req, type) => {
  const frontendBaseURL = process.env.FRONTEND_BASE_URL || `${req.protocol}://${req.get("host")}`;
  // const frontendBaseURL = `${req.protocol}://${req.get("host")}`;

  let url, subject, message;

  if (type === "passwordReset") {
    url = `${frontendBaseURL}/resetPassword/:${token}`;
    subject = "Your Password Reset Token (Valid for 24 hours)";
    message = `
      <p>You requested a password reset. Click the link below to reset your password:</p>
      <p><a href="${url}">${url}</a></p>
      <p>If you didn't request this, please ignore this email.</p>
    `;
  } else if (type === "emailVerification") {
    url = `${frontendBaseURL}/verifyEmail/${token}`;
    subject = "Your Email Verification Token";
    message = `
      <p>Click the link below to verify your email address:</p>
      <p><a href="${url}">${url}</a></p>
      <p>If you didn't request this, please ignore this email.</p>
    `;
  }

  try {
    await sendEmail({
      email: user.email,
      name: user.name,
      subject,
      message,
    });

    return {
      status: "success",
      message: `A ${type === "passwordReset" ? "reset token" : "verification token"} has been sent to your email address. Please check your inbox.`,
    };
  } catch (err) {
    // Cleanup if email fails to send
    if (type === "passwordReset") {
      user.passwordResetToken = undefined;
      user.passwordResetExpires = undefined;
    } else if (type === "emailVerification") {
      user.emailToken = undefined;
    }
    await user.save({ validateBeforeSave: false });

    throw new Error("There was an error sending the email. Please try again later!");
  }
};

module.exports = sendEmailWithToken;