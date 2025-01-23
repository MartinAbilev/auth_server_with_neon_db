const express = require('express');
const cookieParser = require('cookie-parser');
const { Pool } = require('pg');
const uuid = require('uuid');  // Use UUID for session IDs

require('dotenv').config();

const app = express();
const PORT = 3333;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static('public'));

// Initialize PostgreSQL Pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// In-memory store for logged-in users
const usersLogged = {};

// Helper function to validate token
async function authenticateToken(req, res, next) {
  const token = req.cookies.authToken;
  if (!token) return res.redirect('/login.html');

  try {
    const decoded = JSON.parse(Buffer.from(token, 'base64').toString('utf-8'));

    // Check if the session ID exists in the logged-in cache
    const session = usersLogged[decoded.sessionId];
    if (!session) return res.redirect('/login.html');

    req.user = { id: session.userId, sessionId: decoded.sessionId };
    next();
  } catch {
    res.redirect('/login.html');
  }
}

// Routes
app.get('/', authenticateToken, (req, res) => {
  res.sendFile(__dirname + '/public/home.html');
});
app.get('/home', authenticateToken, (req, res) => {
  res.sendFile(__dirname + '/public/home.html');
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const email = username
  try {
    // Query the database for the user
    const result = await pool.query(
      'SELECT id, name FROM users WHERE email = $1 AND password = $2',
      [username, password]
    );

    if (result.rowCount > 0) {
      const user = result.rows[0];

      // Generate a unique session ID
      const sessionId = uuid.v4();

      console.log('USER loged in', user.id, user.name, 'sessionid', sessionId)
      // Generate token and add user to the logged-in cache
      // Store session ID with userId and timestamp
      usersLogged[sessionId] = { sessionId: sessionId, username: user.name, timestamp: Date.now() };

      // Generate token with sessionId
      const token = Buffer.from(JSON.stringify(usersLogged[sessionId])).toString('base64');

      res.cookie('authToken', token, { httpOnly: false });
      res.redirect('/home');
    } else {
      res.redirect('/login.html?error=Invalid credentials');
    }
  } catch (err) {
    console.error(err);
    res.status(500).send('Internal Server Error');
  }
});

// Route to fetch user data based on session ID
app.post('/get-user-data', authenticateToken, (req, res) => {
  const session = usersLogged[req.user.sessionId];
  if (!session) {
    return res.status(401).send({ message: 'Session expired or invalid.' });
  }

  res.send({
    userId: session.userId,
    username: session.username,
    timestamp: session.timestamp,
  });
});

app.get('/logout', (req, res) => {
  const token = req.cookies.authToken;

  if (token) {
    try {
      const decoded = JSON.parse(Buffer.from(token, 'base64').toString('utf-8'));

      // Remove the user from the logged-in cache
      delete usersLogged[decoded.id];
    } catch {
      console.error('Invalid token during logout.');
    }
  }

  res.clearCookie('authToken');
  res.redirect('/login.html');
});

// Start server
app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
