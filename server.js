// server.js

// Load environment variables from .env file
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const app = express();
const PORT = 3000;
const pool = require('./db');
const bcrypt = require('bcrypt');          // for password hashing
const jwt = require('jsonwebtoken');       // for generating/verifying JWTs

// Test database connection
pool.query('SELECT NOW()', (err, res) => {
  if (err) {
    console.error('Database connection failed', err);
  } else {
    console.log('Database connected at', res.rows[0].now);
  }
});

// Middleware to parse JSON request bodies
const allowedOrigins = [
  'http://localhost:5173',
  'https://your-frontend.vercel.app', // replace with actual Vercel URL later
];
app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  }
}));    
app.use(express.json());

// ----------------------------------------------------------------------
// Authentication Middleware
// ----------------------------------------------------------------------
// Verifies the JWT from the Authorization header and attaches the user
// payload to req.user if valid.
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // "Bearer TOKEN"

  if (!token) {
    return res.status(401).json({ message: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid or expired token' });
    }
    req.user = user;   // { userId, email, iat, exp }
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
    // 1. Parse and validate query parameters
    const page = Math.max(parseInt(req.query.page) || 1, 1);
    const limit = Math.max(parseInt(req.query.limit) || 10, 1);
    const order = req.query.order === 'desc' ? 'DESC' : 'ASC';
    const sortBy = req.query.sortBy;               // 'title' or 'author'
    const authorFilter = req.query.author ? req.query.author.trim() : null;

    // 2. Build ORDER BY clause (whitelist to prevent SQL injection)
    let orderByClause = `ORDER BY books.id ASC`;   // default
    if (sortBy === 'title') {
      orderByClause = `ORDER BY books.title ${order}`;
    } else if (sortBy === 'author') {
      orderByClause = `ORDER BY authors.name ${order}`;
    }

    // 3. Build WHERE clause for filtering by author name (exact, case-insensitive)
    const filterParams = [];
    let whereClause = '';
    if (authorFilter) {
      filterParams.push(authorFilter);
      whereClause = `WHERE authors.name ILIKE $1`;
    }

    // 4. Get total count after filtering (separate query)
    const countQuery = `
      SELECT COUNT(*)::int AS total
      FROM books
      JOIN authors ON books.author_id = authors.id
      ${whereClause}
    `;
    const countResult = await pool.query(countQuery, filterParams);
    const total = countResult.rows[0].total;

    // 5. Fetch paginated data with JOIN
    const offset = (page - 1) * limit;
    const dataQuery = `
      SELECT books.id, books.title, authors.name AS author, books.author_id
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

    // 6. Return response with metadata
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

// GET /books/:id - get one book by ID (with author name)
app.get('/books/:id', async (req, res) => {
  const id = Number(req.params.id);
  if (isNaN(id)) {
    return res.status(400).json({ message: 'Invalid id' });
  }

  try {
    const result = await pool.query(
      `SELECT books.id, books.title, authors.name AS author, books.author_id
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
  const { title, authorId } = req.body;

  // Validate title
  if (typeof title !== 'string' || title.trim() === '') {
    return res.status(400).json({ message: 'Title must be a non-empty string' });
  }
  // Validate authorId
  if (!Number.isInteger(authorId) || authorId <= 0) {
    return res.status(400).json({ message: 'authorId must be a positive integer' });
  }

  try {
    // Check if author exists
    const authorCheck = await pool.query('SELECT id FROM authors WHERE id = $1', [authorId]);
    if (authorCheck.rows.length === 0) {
      return res.status(400).json({ message: 'Author does not exist' });
    }

    // Insert book
    const result = await pool.query(
      'INSERT INTO books (title, author_id) VALUES ($1, $2) RETURNING *',
      [title.trim(), authorId]
    );

    // Fetch the joined result for consistent response
    const book = await pool.query(
      `SELECT books.id, books.title, authors.name AS author
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

// PATCH /books/:id - update a book's title and/or author (requires authentication)
app.patch('/books/:id', authenticateToken, async (req, res) => {
  const id = Number(req.params.id);
  if (isNaN(id)) {
    return res.status(400).json({ message: 'Invalid id' });
  }

  const { title, authorId } = req.body;

  // Validate if provided
  if (title !== undefined && (typeof title !== 'string' || title.trim() === '')) {
    return res.status(400).json({ message: 'Title must be a non-empty string' });
  }
  if (authorId !== undefined && (!Number.isInteger(authorId) || authorId <= 0)) {
    return res.status(400).json({ message: 'authorId must be a positive integer' });
  }

  try {
    // Fetch existing book
    const existing = await pool.query('SELECT * FROM books WHERE id = $1', [id]);
    if (existing.rows.length === 0) {
      return res.status(404).json({ message: 'Book not found' });
    }
    const current = existing.rows[0];

    // Determine new values (use existing if not provided)
    const newTitle = title !== undefined ? title.trim() : current.title;
    const newAuthorId = authorId !== undefined ? authorId : current.author_id;

    // If authorId is being changed, verify the new author exists
    if (authorId !== undefined) {
      const authorCheck = await pool.query('SELECT id FROM authors WHERE id = $1', [authorId]);
      if (authorCheck.rows.length === 0) {
        return res.status(400).json({ message: 'Author does not exist' });
      }
    }

    // Update the book
    await pool.query(
      'UPDATE books SET title = $1, author_id = $2 WHERE id = $3',
      [newTitle, newAuthorId, id]
    );

    // Fetch the updated book with join for response
    const updated = await pool.query(
      `SELECT books.id, books.title, authors.name AS author
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

// DELETE /books/:id - delete a book (requires authentication)
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
// Author Routes
// ----------------------------------------------------------------------

// GET /authors - list all authors with book counts
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

// GET /authors/:id - get one author with their books
app.get('/authors/:id', async (req, res) => {
  const id = Number(req.params.id);
  if (isNaN(id)) {
    return res.status(400).json({ message: 'Invalid id' });
  }

  try {
    // Fetch author info
    const authorResult = await pool.query('SELECT id, name FROM authors WHERE id = $1', [id]);
    if (authorResult.rows.length === 0) {
      return res.status(404).json({ message: 'Author not found' });
    }

    // Fetch books by this author
    const booksResult = await pool.query(
      'SELECT id, title FROM books WHERE author_id = $1',
      [id]
    );

    // Combine into one response
    res.json({
      ...authorResult.rows[0],
      books: booksResult.rows,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// POST /authors - create a new author (requires authentication)
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
    // Unique violation (duplicate name)
    if (err.code === '23505') {
      return res.status(409).json({ message: 'Author already exists' });
    }
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// PATCH /authors/:id - update author name (requires authentication)
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

// DELETE /authors/:id - delete author and cascade delete their books (requires authentication)
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

// POST /auth/register - register a new user
app.post('/auth/register', async (req, res) => {
  const { email, password } = req.body;

  // Basic validation
  if (typeof email !== 'string' || email.trim() === '' || !email.includes('@')) {
    return res.status(400).json({ message: 'Valid email is required' });
  }
  if (typeof password !== 'string' || password.length < 6) {
    return res.status(400).json({ message: 'Password must be at least 6 characters' });
  }

  try {
    // Check if email already exists
    const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email.trim().toLowerCase()]);
    if (existing.rows.length > 0) {
      return res.status(409).json({ message: 'Email already registered' });
    }

    // Hash the password with bcrypt
    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // Insert user into database
    const result = await pool.query(
      'INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email, created_at',
      [email.trim().toLowerCase(), passwordHash]
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
    // Find user by email
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email.trim().toLowerCase()]);
    if (result.rows.length === 0) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    const user = result.rows[0];

    // Compare provided password with stored hash
    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    // Generate JWT (payload includes userId and email)
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    // Send token and user info (never include password_hash)
    res.json({
      token,
      user: { id: user.id, email: user.email },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// GET /auth/me - get current authenticated user (requires valid JWT)
app.get('/auth/me', authenticateToken, async (req, res) => {
  try {
    // req.user was set by the authenticateToken middleware
    const result = await pool.query(
      'SELECT id, email, created_at FROM users WHERE id = $1',
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

// ----------------------------------------------------------------------
// Start server
// ----------------------------------------------------------------------
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});