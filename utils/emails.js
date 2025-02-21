import "dotenv/config";
// import { MailerSend, EmailParams, Sender, Recipient } from "mailersend";
import { Resend } from "resend";

const resend = new Resend("re_SbKDqhwS_QC1djXMU85FXrBcFm8w7PsHP");

async function sendEmail(options) {
  try {
    const { data, error } = await resend.emails.send({
      from: "Task Managser <onboarding@deniskyu.com>",
      to: [options.email],
      subject: options.subject,
      html: options.message,
    });

    if (error) {
      return console.error({ error });
    }

    // console.log({data})
    return { data };
  } catch (error) {
    console.error("Error sending email:", error.body.message, error.stack); // Enhanced error logging
    throw error; // Rethrow the error to handle it in the calling function
  }
}

export default sendEmail;
