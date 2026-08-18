// server.js

// Load environment variables from .env file
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const app = express();
const PORT = process.env.PORT || 3000;
const pool = require('./db');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// Test database connection
pool.query('SELECT NOW()', (err, res) => {
  if (err) {
    console.error('Database connection failed', err);
  } else {
    console.log('Database connected at', res.rows[0].now);
  }
});

// Middleware
app.use(cors());
app.use(express.json());

// ----------------------------------------------------------------------
// Authentication Middleware
// ----------------------------------------------------------------------
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
}

// ----------------------------------------------------------------------
// Authorization Middleware for Roles
// ----------------------------------------------------------------------
function authorize(...roles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ message: 'Unauthorized' });
    }
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ message: 'Forbidden: insufficient permissions' });
    }
    next();
  };
}

// ----------------------------------------------------------------------
// Root endpoint
// ----------------------------------------------------------------------
app.get('/', (req, res) => {
  res.send('Library API is running');
});

// ----------------------------------------------------------------------
// User Routes (Admin only)
// ----------------------------------------------------------------------
app.get('/users', authenticateToken, authorize('admin'), async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, email, username, role, avatar_url, created_at FROM users ORDER BY id'
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// PATCH /users/:id/role - Admin can change user roles
app.patch('/users/:id/role', authenticateToken, authorize('admin'), async (req, res) => {
  const userId = Number(req.params.id);
  const { role } = req.body;

  if (isNaN(userId)) {
    return res.status(400).json({ message: 'Invalid user id' });
  }
  if (!role || !['admin', 'librarian', 'member'].includes(role)) {
    return res.status(400).json({ message: 'Invalid role' });
  }

  try {
    const result = await pool.query(
      'UPDATE users SET role = $1 WHERE id = $2 RETURNING id, email, username, role',
      [role, userId]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// ----------------------------------------------------------------------
// Book Routes
// ----------------------------------------------------------------------

// GET /books - list all books with advanced filtering, sorting, and pagination
app.get('/books', async (req, res) => {
  try {
    const page = Math.max(parseInt(req.query.page) || 1, 1);
    const limit = Math.max(parseInt(req.query.limit) || 10, 1);
    const order = req.query.order === 'desc' ? 'DESC' : 'ASC';
    const sortBy = req.query.sortBy;

    const { title, author, genre, year, isbn } = req.query;

    // Build dynamic WHERE clause
    const conditions = [];
    const params = [];

    // Helper to conditionally add a condition
    const addCondition = (sql, value) => {
      if (value !== undefined && value !== null && value !== '') {
        if (typeof value === 'string' && value.trim() === '') return;
        conditions.push(sql);
        params.push(value);
      }
    };

    if (author && author.trim() !== '') {
      conditions.push(`authors.name ILIKE $${params.length + 1}`);
      params.push(`%${author.trim()}%`);
    }
    if (title && title.trim() !== '') {
      conditions.push(`books.title ILIKE $${params.length + 1}`);
      params.push(`%${title.trim()}%`);
    }
    if (genre && genre.trim() !== '') {
      conditions.push(`books.genre ILIKE $${params.length + 1}`);
      params.push(`%${genre.trim()}%`);
    }
    if (year && !isNaN(parseInt(year)) && parseInt(year) > 0) {
      conditions.push(`books.publication_year = $${params.length + 1}`);
      params.push(parseInt(year));
    }
    if (isbn && isbn.trim() !== '') {
      conditions.push(`books.isbn ILIKE $${params.length + 1}`);
      params.push(`%${isbn.trim()}%`);
    }

    let whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    // ORDER BY clause (whitelisted)
    let orderByClause = `ORDER BY books.id ASC`;
    if (sortBy === 'title') {
      orderByClause = `ORDER BY books.title ${order}`;
    } else if (sortBy === 'author') {
      orderByClause = `ORDER BY authors.name ${order}`;
    } else if (sortBy === 'year') {
      orderByClause = `ORDER BY books.publication_year ${order}`;
    }

    // Count query
    const countQuery = `
      SELECT COUNT(*)::int AS total
      FROM books
      JOIN authors ON books.author_id = authors.id
      ${whereClause}
    `;
    const countResult = await pool.query(countQuery, params);
    const total = countResult.rows[0].total;

    // Data query with is_borrowed
    const offset = (page - 1) * limit;
    const dataQuery = `
      SELECT books.id, books.title, authors.name AS author, books.author_id, books.cover_image_url,
             books.genre, books.publication_year, books.isbn,
             EXISTS (
               SELECT 1 FROM loans l
               WHERE l.book_id = books.id AND l.returned_at IS NULL
             ) AS is_borrowed
      FROM books
      JOIN authors ON books.author_id = authors.id
      ${whereClause}
      ${orderByClause}
      LIMIT $${params.length + 1}
      OFFSET $${params.length + 2}
    `;
    const dataResult = await pool.query(dataQuery, [...params, limit, offset]);

    res.json({
      data: dataResult.rows,
      total,
      page,
      limit,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// GET /books/:id - get one book by ID
app.get('/books/:id', async (req, res) => {
  const id = Number(req.params.id);
  if (isNaN(id)) {
    return res.status(400).json({ message: 'Invalid id' });
  }

  try {
    const result = await pool.query(
      `SELECT books.id, books.title, authors.name AS author, books.author_id, books.cover_image_url,
              books.genre, books.publication_year, books.isbn,
              EXISTS (
                SELECT 1 FROM loans l
                WHERE l.book_id = books.id AND l.returned_at IS NULL
              ) AS is_borrowed
       FROM books
       JOIN authors ON books.author_id = authors.id
       WHERE books.id = $1`,
      [id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Book not found' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// POST /books - requires 'admin' or 'librarian'
app.post('/books', authenticateToken, authorize('admin', 'librarian'), async (req, res) => {
  const { title, authorId, coverImageUrl, genre, publicationYear, isbn } = req.body;

  if (typeof title !== 'string' || title.trim() === '') {
    return res.status(400).json({ message: 'Title must be a non-empty string' });
  }
  if (!Number.isInteger(authorId) || authorId <= 0) {
    return res.status(400).json({ message: 'authorId must be a positive integer' });
  }
  if (coverImageUrl !== undefined && typeof coverImageUrl !== 'string') {
    return res.status(400).json({ message: 'coverImageUrl must be a string' });
  }
  if (genre !== undefined && typeof genre !== 'string') {
    return res.status(400).json({ message: 'genre must be a string' });
  }
  if (publicationYear !== undefined && (!Number.isInteger(publicationYear) || publicationYear < 0)) {
    return res.status(400).json({ message: 'publicationYear must be a positive integer' });
  }
  if (isbn !== undefined && typeof isbn !== 'string') {
    return res.status(400).json({ message: 'isbn must be a string' });
  }

  try {
    const authorCheck = await pool.query('SELECT id FROM authors WHERE id = $1', [authorId]);
    if (authorCheck.rows.length === 0) {
      return res.status(400).json({ message: 'Author does not exist' });
    }

    const result = await pool.query(
      `INSERT INTO books (title, author_id, cover_image_url, genre, publication_year, isbn)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
      [title.trim(), authorId, coverImageUrl || null, genre || null, publicationYear || null, isbn || null]
    );

    const book = await pool.query(
      `SELECT books.id, books.title, authors.name AS author, books.author_id, books.cover_image_url,
              books.genre, books.publication_year, books.isbn,
              false AS is_borrowed
       FROM books
       JOIN authors ON books.author_id = authors.id
       WHERE books.id = $1`,
      [result.rows[0].id]
    );
    res.status(201).json(book.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// PATCH /books/:id - requires 'admin' or 'librarian'
app.patch('/books/:id', authenticateToken, authorize('admin', 'librarian'), async (req, res) => {
  const id = Number(req.params.id);
  if (isNaN(id)) {
    return res.status(400).json({ message: 'Invalid id' });
  }

  const { title, authorId, coverImageUrl, genre, publicationYear, isbn } = req.body;

  if (title !== undefined && (typeof title !== 'string' || title.trim() === '')) {
    return res.status(400).json({ message: 'Title must be a non-empty string' });
  }
  if (authorId !== undefined && (!Number.isInteger(authorId) || authorId <= 0)) {
    return res.status(400).json({ message: 'authorId must be a positive integer' });
  }
  if (coverImageUrl !== undefined && typeof coverImageUrl !== 'string') {
    return res.status(400).json({ message: 'coverImageUrl must be a string' });
  }
  if (genre !== undefined && typeof genre !== 'string') {
    return res.status(400).json({ message: 'genre must be a string' });
  }
  if (publicationYear !== undefined && (!Number.isInteger(publicationYear) || publicationYear < 0)) {
    return res.status(400).json({ message: 'publicationYear must be a positive integer' });
  }
  if (isbn !== undefined && typeof isbn !== 'string') {
    return res.status(400).json({ message: 'isbn must be a string' });
  }

  try {
    const existing = await pool.query('SELECT * FROM books WHERE id = $1', [id]);
    if (existing.rows.length === 0) {
      return res.status(404).json({ message: 'Book not found' });
    }
    const current = existing.rows[0];

    const newTitle = title !== undefined ? title.trim() : current.title;
    const newAuthorId = authorId !== undefined ? authorId : current.author_id;
    const newCoverImageUrl = coverImageUrl !== undefined ? coverImageUrl : current.cover_image_url;
    const newGenre = genre !== undefined ? genre : current.genre;
    const newPublicationYear = publicationYear !== undefined ? publicationYear : current.publication_year;
    const newIsbn = isbn !== undefined ? isbn : current.isbn;

    if (authorId !== undefined) {
      const authorCheck = await pool.query('SELECT id FROM authors WHERE id = $1', [authorId]);
      if (authorCheck.rows.length === 0) {
        return res.status(400).json({ message: 'Author does not exist' });
      }
    }

    await pool.query(
      `UPDATE books SET title = $1, author_id = $2, cover_image_url = $3, genre = $4,
       publication_year = $5, isbn = $6 WHERE id = $7`,
      [newTitle, newAuthorId, newCoverImageUrl, newGenre, newPublicationYear, newIsbn, id]
    );

    const updated = await pool.query(
      `SELECT books.id, books.title, authors.name AS author, books.author_id, books.cover_image_url,
              books.genre, books.publication_year, books.isbn,
              EXISTS (
                SELECT 1 FROM loans l
                WHERE l.book_id = books.id AND l.returned_at IS NULL
              ) AS is_borrowed
       FROM books
       JOIN authors ON books.author_id = authors.id
       WHERE books.id = $1`,
      [id]
    );
    res.json(updated.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// DELETE /books/:id - requires 'admin' or 'librarian'
app.delete('/books/:id', authenticateToken, authorize('admin', 'librarian'), async (req, res) => {
  const id = Number(req.params.id);
  if (isNaN(id)) {
    return res.status(400).json({ message: 'Invalid id' });
  }

  try {
    const result = await pool.query('DELETE FROM books WHERE id = $1 RETURNING id', [id]);
    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Book not found' });
    }
    res.status(204).send();
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// ----------------------------------------------------------------------
// Author Routes
// ----------------------------------------------------------------------

app.get('/authors', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT authors.id, authors.name, COUNT(books.id)::int AS book_count
      FROM authors
      LEFT JOIN books ON books.author_id = authors.id
      GROUP BY authors.id
      ORDER BY authors.name ASC
    `);
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/authors/:id', async (req, res) => {
  const id = Number(req.params.id);
  if (isNaN(id)) {
    return res.status(400).json({ message: 'Invalid id' });
  }

  try {
    const authorResult = await pool.query('SELECT id, name FROM authors WHERE id = $1', [id]);
    if (authorResult.rows.length === 0) {
      return res.status(404).json({ message: 'Author not found' });
    }

    const booksResult = await pool.query(
      'SELECT id, title, cover_image_url, genre, publication_year, isbn FROM books WHERE author_id = $1',
      [id]
    );

    res.json({
      ...authorResult.rows[0],
      books: booksResult.rows,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/authors', authenticateToken, authorize('admin', 'librarian'), async (req, res) => {
  const { name } = req.body;

  if (typeof name !== 'string' || name.trim() === '') {
    return res.status(400).json({ message: 'Name must be a non-empty string' });
  }

  try {
    const result = await pool.query(
      'INSERT INTO authors (name) VALUES ($1) RETURNING id, name',
      [name.trim()]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ message: 'Author already exists' });
    }
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.patch('/authors/:id', authenticateToken, authorize('admin', 'librarian'), async (req, res) => {
  const id = Number(req.params.id);
  if (isNaN(id)) {
    return res.status(400).json({ message: 'Invalid id' });
  }
  const { name } = req.body;
  if (typeof name !== 'string' || name.trim() === '') {
    return res.status(400).json({ message: 'Name must be a non-empty string' });
  }

  try {
    const result = await pool.query(
      'UPDATE authors SET name = $1 WHERE id = $2 RETURNING id, name',
      [name.trim(), id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Author not found' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ message: 'Author name already exists' });
    }
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.delete('/authors/:id', authenticateToken, authorize('admin', 'librarian'), async (req, res) => {
  const id = Number(req.params.id);
  if (isNaN(id)) {
    return res.status(400).json({ message: 'Invalid id' });
  }

  try {
    const result = await pool.query('DELETE FROM authors WHERE id = $1 RETURNING id', [id]);
    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Author not found' });
    }
    res.status(204).send();
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// ----------------------------------------------------------------------
// Authentication Routes (with role)
// ----------------------------------------------------------------------

app.post('/auth/register', async (req, res) => {
  const { email, password, username } = req.body;

  if (typeof email !== 'string' || email.trim() === '' || !email.includes('@')) {
    return res.status(400).json({ message: 'Valid email is required' });
  }
  if (typeof password !== 'string' || password.length < 6) {
    return res.status(400).json({ message: 'Password must be at least 6 characters' });
  }
  if (typeof username !== 'string' || username.trim() === '') {
    return res.status(400).json({ message: 'Username is required' });
  }

  try {
    const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email.trim().toLowerCase()]);
    if (existing.rows.length > 0) {
      return res.status(409).json({ message: 'Email already registered' });
    }

    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    const result = await pool.query(
      'INSERT INTO users (email, password_hash, username, role) VALUES ($1, $2, $3, $4) RETURNING id, email, username, role, created_at',
      [email.trim().toLowerCase(), passwordHash, username.trim(), 'member']
    );

    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;

  if (typeof email !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ message: 'Email and password are required' });
  }

  try {
    const result = await pool.query(
      'SELECT id, email, username, avatar_url, role, password_hash FROM users WHERE email = $1',
      [email.trim().toLowerCase()]
    );
    if (result.rows.length === 0) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    const user = result.rows[0];

    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    const token = jwt.sign(
      { userId: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
        avatar_url: user.avatar_url,
        role: user.role,
      },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/auth/me', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, email, username, avatar_url, role, created_at FROM users WHERE id = $1',
      [req.user.userId]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.patch('/auth/me', authenticateToken, async (req, res) => {
  const { username, avatarUrl } = req.body;

  if (username !== undefined && (typeof username !== 'string' || username.trim() === '')) {
    return res.status(400).json({ message: 'Username must be a non-empty string' });
  }
  if (avatarUrl !== undefined && typeof avatarUrl !== 'string') {
    return res.status(400).json({ message: 'Avatar URL must be a string' });
  }

  try {
    const fields = [];
    const values = [];
    let index = 1;

    if (username !== undefined) {
      fields.push(`username = $${index}`);
      values.push(username.trim());
      index++;
    }
    if (avatarUrl !== undefined) {
      fields.push(`avatar_url = $${index}`);
      values.push(avatarUrl);
      index++;
    }

    if (fields.length === 0) {
      return res.status(400).json({ message: 'No fields to update' });
    }

    values.push(req.user.userId);
    const setClause = fields.join(', ');
    const result = await pool.query(
      `UPDATE users SET ${setClause} WHERE id = $${index} RETURNING id, email, username, avatar_url, role, created_at`,
      values
    );

    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// ----------------------------------------------------------------------
// Loan Routes
// ----------------------------------------------------------------------

// GET /loans - get current user's loans (active & history)
app.get('/loans', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT l.id, l.book_id, l.borrowed_at, l.due_date, l.returned_at,
              b.title, a.name AS author, b.cover_image_url
       FROM loans l
       JOIN books b ON l.book_id = b.id
       JOIN authors a ON b.author_id = a.id
       WHERE l.user_id = $1
       ORDER BY l.borrowed_at DESC`,
      [req.user.userId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// POST /loans - borrow a book
app.post('/loans', authenticateToken, async (req, res) => {
  const { bookId } = req.body;
  const userId = req.user.userId;

  if (!Number.isInteger(bookId) || bookId <= 0) {
    return res.status(400).json({ message: 'Valid bookId required' });
  }

  try {
    const bookCheck = await pool.query('SELECT id FROM books WHERE id = $1', [bookId]);
    if (bookCheck.rows.length === 0) {
      return res.status(404).json({ message: 'Book not found' });
    }

    const activeLoan = await pool.query(
      'SELECT id FROM loans WHERE book_id = $1 AND returned_at IS NULL',
      [bookId]
    );
    if (activeLoan.rows.length > 0) {
      return res.status(409).json({ message: 'Book is currently borrowed' });
    }

    const dueDate = new Date();
    dueDate.setDate(dueDate.getDate() + 14);

    const result = await pool.query(
      `INSERT INTO loans (book_id, user_id, due_date)
       VALUES ($1, $2, $3)
       RETURNING id, book_id, user_id, borrowed_at, due_date`,
      [bookId, userId, dueDate]
    );

    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// PATCH /loans/:id/return - return a borrowed book
app.patch('/loans/:id/return', authenticateToken, async (req, res) => {
  const loanId = Number(req.params.id);
  if (isNaN(loanId)) {
    return res.status(400).json({ message: 'Invalid loan id' });
  }

  try {
    const loanCheck = await pool.query(
      'SELECT id, user_id FROM loans WHERE id = $1 AND returned_at IS NULL',
      [loanId]
    );
    if (loanCheck.rows.length === 0) {
      return res.status(404).json({ message: 'Active loan not found' });
    }
    const loan = loanCheck.rows[0];
    if (loan.user_id !== req.user.userId) {
      return res.status(403).json({ message: 'You do not own this loan' });
    }

    await pool.query(
      'UPDATE loans SET returned_at = NOW() WHERE id = $1',
      [loanId]
    );

    res.json({ message: 'Book returned successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// ----------------------------------------------------------------------
// Start server
// ----------------------------------------------------------------------
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});