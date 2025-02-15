import 'dotenv/config';
import { MailerSend, EmailParams, Sender, Recipient } from 'mailersend';

async function sendEmail  (options) {
  try {
    console.log('sendEmail called with options:', options);

    if (!process.env.MAILERSEND_API_KEY) {
      throw new Error('MAILERSEND_API_KEY is not defined in environment variables');
    }

    // Validate options
    if (!options.email || !options.name || !options.subject || !options.message) {
      throw new Error('Missing required options for email sending.');
    }

    // Initialize MailerSend with API key
    const mailerSend = new MailerSend({
      apiKey: process.env.MAILERSEND_API_KEY,
      baseUrl: process.env.MAILERSEND_BASE_URL,
    });

    // Define sender
    const sentFrom = new Sender("MS_wqzj2D@trial-pr9084z0vvelw63d.mlsender.net", "Task Manager");

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
    return response;

  } catch (error) {
    console.error('Error sending email:', error.message, error.stack); // Enhanced error logging
    throw error; // Rethrow the error to handle it in the calling function
  }
};

export default sendEmail;
