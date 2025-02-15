import 'dotenv/config';
import { MailerSend, EmailParams, Sender, Recipient } from 'mailersend'; // Use ES module imports

// Function to send verification email
const sendEmail = async (options) => {
  try {
console.log('sendEmail called with options:', options); // Log incoming options

    if (!process.env.MAILERSEND_API_KEY) {
      throw new Error('MAILERSEND_API_KEY is not defined in environment variables');
    }

    // Initialize MailerSend with API key
    const mailerSend = new MailerSend({
      apiKey: process.env.MAILERSEND_API_KEY,
    });

    // Define sender
    const sentFrom = new Sender(process.env.EMAIL_SENDER, "Task Manager");

    // Define recipient(s)
    const recipients = [new Recipient(options.email, options.name)];

    // Configure email parameters
    const emailParams = new EmailParams()
      .setFrom(sentFrom)
      .setTo(recipients)
      .setReplyTo(sentFrom)
      .setSubject(options.subject)
      .setHtml(options.message);

    // Send email
    const response = await mailerSend.email.send(emailParams);
    console.log('Email sent successfully:', response);
  } catch (error) {
    console.error('Error sending email:', error);
  }
};

export default sendEmail;