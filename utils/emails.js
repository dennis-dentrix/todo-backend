const nodemailer = require("nodemailer");

const sendEmail = async (options) => {
  // CREATE TRANSPORTER
  const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: process.env.EMAIL_PORT,
    auth: {
      user: process.env.EMAIL_USERNAME,
      pass: process.env.EMAIL_PASSWORD,
    },
  });
  // DEFINE EMAIL OPTIONS
  const mailOptions = {
    from: "Denis Kyusya <admin@gmail.com>",
    to: options.email,
    subject: options.subject,
    text: options.message,
  };
  // SEND THE ACTUAL EMAIL
  await transporter.sendMail(mailOptions);
};


module.exports = sendEmail;
