const { Resend } = require('resend');
require('dotenv').config();

const resend = new Resend(process.env.RESEND_API_KEY);

async function test() {
  const { data, error } = await resend.emails.send({
    from: process.env.RESEND_FROM_EMAIL || 'onboarding@resend.dev',
    to: 'thabangmoshka@gmail.com',   // replace with your real email
    subject: 'Test from Resend',
    html: '<p>Hello, this is a test.</p>',
  });
  console.log({ data, error });
}

test();