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
// Root endpoint
// ----------------------------------------------------------------------
app.get('/', (req, res) => {
  res.send('Library API is running');
});

// ----------------------------------------------------------------------
// Book Routes
// ----------------------------------------------------------------------

// GET /books - list all books with optional filtering, sorting, and pagination
app.get('/books', async (req, res) => {
  try {
    const page = Math.max(parseInt(req.query.page) || 1, 1);
    const limit = Math.max(parseInt(req.query.limit) || 10, 1);
    const order = req.query.order === 'desc' ? 'DESC' : 'ASC';
    const sortBy = req.query.sortBy;
    const authorFilter = req.query.author ? req.query.author.trim() : null;

    let orderByClause = `ORDER BY books.id ASC`;
    if (sortBy === 'title') {
      orderByClause = `ORDER BY books.title ${order}`;
    } else if (sortBy === 'author') {
      orderByClause = `ORDER BY authors.name ${order}`;
    }

    const filterParams = [];
    let whereClause = '';
    if (authorFilter) {
      filterParams.push(authorFilter);
      whereClause = `WHERE authors.name ILIKE $1`;
    }

    const countQuery = `
      SELECT COUNT(*)::int AS total
      FROM books
      JOIN authors ON books.author_id = authors.id
      ${whereClause}
    `;
    const countResult = await pool.query(countQuery, filterParams);
    const total = countResult.rows[0].total;

    const offset = (page - 1) * limit;
    const dataQuery = `
      SELECT books.id, books.title, authors.name AS author, books.author_id, books.cover_image_url
      FROM books
      JOIN authors ON books.author_id = authors.id
      ${whereClause}
      ${orderByClause}
      LIMIT $${filterParams.length + 1}
      OFFSET $${filterParams.length + 2}
    `;
    const dataResult = await pool.query(dataQuery, [
      ...filterParams,
      limit,
      offset,
    ]);

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
      `SELECT books.id, books.title, authors.name AS author, books.author_id, books.cover_image_url
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

// POST /books - create a new book (requires authentication)
app.post('/books', authenticateToken, async (req, res) => {
  const { title, authorId, coverImageUrl } = req.body;

  if (typeof title !== 'string' || title.trim() === '') {
    return res.status(400).json({ message: 'Title must be a non-empty string' });
  }
  if (!Number.isInteger(authorId) || authorId <= 0) {
    return res.status(400).json({ message: 'authorId must be a positive integer' });
  }
  if (coverImageUrl !== undefined && typeof coverImageUrl !== 'string') {
    return res.status(400).json({ message: 'coverImageUrl must be a string' });
  }

  try {
    const authorCheck = await pool.query('SELECT id FROM authors WHERE id = $1', [authorId]);
    if (authorCheck.rows.length === 0) {
      return res.status(400).json({ message: 'Author does not exist' });
    }

    const result = await pool.query(
      'INSERT INTO books (title, author_id, cover_image_url) VALUES ($1, $2, $3) RETURNING *',
      [title.trim(), authorId, coverImageUrl || null]
    );

    const book = await pool.query(
      `SELECT books.id, books.title, authors.name AS author, books.author_id, books.cover_image_url
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

// PATCH /books/:id - update a book's title and/or author
app.patch('/books/:id', authenticateToken, async (req, res) => {
  const id = Number(req.params.id);
  if (isNaN(id)) {
    return res.status(400).json({ message: 'Invalid id' });
  }

  const { title, authorId, coverImageUrl } = req.body;

  if (title !== undefined && (typeof title !== 'string' || title.trim() === '')) {
    return res.status(400).json({ message: 'Title must be a non-empty string' });
  }
  if (authorId !== undefined && (!Number.isInteger(authorId) || authorId <= 0)) {
    return res.status(400).json({ message: 'authorId must be a positive integer' });
  }
  if (coverImageUrl !== undefined && typeof coverImageUrl !== 'string') {
    return res.status(400).json({ message: 'coverImageUrl must be a string' });
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

    if (authorId !== undefined) {
      const authorCheck = await pool.query('SELECT id FROM authors WHERE id = $1', [authorId]);
      if (authorCheck.rows.length === 0) {
        return res.status(400).json({ message: 'Author does not exist' });
      }
    }

    await pool.query(
      'UPDATE books SET title = $1, author_id = $2, cover_image_url = $3 WHERE id = $4',
      [newTitle, newAuthorId, newCoverImageUrl, id]
    );

    const updated = await pool.query(
      `SELECT books.id, books.title, authors.name AS author, books.author_id, books.cover_image_url
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

// DELETE /books/:id - delete a book
app.delete('/books/:id', authenticateToken, async (req, res) => {
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
// Author Routes (unchanged)
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
      'SELECT id, title, cover_image_url FROM books WHERE author_id = $1',
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

app.post('/authors', authenticateToken, async (req, res) => {
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

app.patch('/authors/:id', authenticateToken, async (req, res) => {
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

app.delete('/authors/:id', authenticateToken, async (req, res) => {
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
// Authentication Routes
// ----------------------------------------------------------------------

// POST /auth/register - register a new user with username
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
      'INSERT INTO users (email, password_hash, username) VALUES ($1, $2, $3) RETURNING id, email, username, created_at',
      [email.trim().toLowerCase(), passwordHash, username.trim()]
    );

    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// POST /auth/login - login and receive a JWT
app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;

  if (typeof email !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ message: 'Email and password are required' });
  }

  try {
    const result = await pool.query(
      'SELECT id, email, username, avatar_url, password_hash FROM users WHERE email = $1',
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
      { userId: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
        avatar_url: user.avatar_url,
      },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// GET /auth/me - get current authenticated user
app.get('/auth/me', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, email, username, avatar_url, created_at FROM users WHERE id = $1',
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

// PATCH /auth/me - update user profile (username, avatar_url)
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
      `UPDATE users SET ${setClause} WHERE id = $${index} RETURNING id, email, username, avatar_url, created_at`,
      values
    );

    res.json(result.rows[0]);
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