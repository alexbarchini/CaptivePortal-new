const { Pool } = require('pg');

const pool = new Pool({
  host: process.env.DB_HOST || 'postgres',
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || 'portal',
  password: process.env.DB_PASSWORD || 'portal123',
  database: process.env.DB_NAME || 'captive_portal'
});

module.exports = { pool };
