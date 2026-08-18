const { Resend } = require('resend');

const resend = new Resend(process.env.RESEND_API_KEY);

/**
 * Send a welcome email after registration
 */
const sendWelcomeEmail = async (email, username) => {
  try {
    const { data, error } = await resend.emails.send({
      from: process.env.RESEND_FROM_EMAIL || 'onboarding@resend.dev',
      to: email,
      subject: 'Welcome to the Library App!',
      html: `
        <h1>Welcome, ${username}!</h1>
        <p>Thank you for joining our library community. Start exploring thousands of books today.</p>
        <p><a href="https://your-frontend-url.com/books" style="background:#6366f1;color:white;padding:10px 20px;border-radius:8px;text-decoration:none;">Browse Books</a></p>
        <p>Happy reading!</p>
        <p>The Library Team</p>
      `,
    });
    if (error) console.error('Welcome email error:', error);
    return { data, error };
  } catch (error) {
    console.error('Failed to send welcome email:', error);
    return { error };
  }
};

/**
 * Send an overdue reminder for borrowed books
 */
const sendOverdueReminder = async (email, username, overdueBooks) => {
  if (!overdueBooks || overdueBooks.length === 0) return;

  const bookList = overdueBooks
    .map(b => `<li><strong>${b.title}</strong> – due ${new Date(b.due_date).toLocaleDateString()}</li>`)
    .join('');

  try {
    const { data, error } = await resend.emails.send({
      from: process.env.RESEND_FROM_EMAIL || 'onboarding@resend.dev',
      to: email,
      subject: '📚 Your books are overdue!',
      html: `
        <h2>Hi ${username},</h2>
        <p>The following books are overdue. Please return them soon:</p>
        <ul>${bookList}</ul>
        <p><a href="https://your-frontend-url.com/loans" style="background:#6366f1;color:white;padding:10px 20px;border-radius:8px;text-decoration:none;">View your loans</a></p>
        <p>Thanks,<br/>The Library Team</p>
      `,
    });
    if (error) console.error('Overdue reminder error:', error);
    return { data, error };
  } catch (error) {
    console.error('Failed to send overdue reminder:', error);
    return { error };
  }
};

module.exports = { sendWelcomeEmail, sendOverdueReminder };