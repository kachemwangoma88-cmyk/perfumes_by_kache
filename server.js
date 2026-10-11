require('dotenv').config();

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const express = require('express');
const axios = require('axios');
const cors = require('cors');
const helmet = require('helmet');
const session = require('express-session');
const PgSession = require('connect-pg-simple')(session);
const { Pool } = require('pg');
const argon2 = require('argon2');
const multer = require('multer');

const app = express();

// Database Pool Setup
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// 1. STANDARD MIDDLEWARE
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static files from root directory
app.use(express.static(__dirname));

// 2. GLOBAL REQUEST LOGGER
app.use((req, res, next) => {
  console.log(`[REQUEST] ${req.method} ${req.url}`);
  next();
});

// 3. YOUR ROUTERS & ROUTES
app.get('/', (req, res) => {
  res.send('Perfumes by Kache API is running');
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'), (err) => {
    if (err) {
      console.error('File send error:', err);
      res.status(500).json({ 
        status: 'Failed to serve index.html', 
        errorMessage: err.message, 
        attemptedPath: err.path 
      });
    }
  });
});

// 4. GLOBAL ERROR HANDLER
app.use((err, req, res, next) => {
  console.error('SERVER ERROR:', err.stack || err);
  res.status(500).json({ error: err.message || 'An unexpected server error occurred.' });
});

// 5. START SERVER
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Perfumes by Kache API listening on port ${PORT}`);
});

module.exports = { app, pool };
