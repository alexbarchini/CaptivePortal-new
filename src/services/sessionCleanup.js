const { pool } = require('../db');
const { logError, logInfo } = require('../utils/logger');

async function enforceMaxOpenSessions(userId, keepLsid, maxOpen = 5) {
  const parsedUserId = Number(userId);
  const parsedMaxOpen = Number(maxOpen);

  if (!Number.isInteger(parsedUserId) || parsedUserId <= 0) return { closedCount: 0, closedLsids: [] };
  if (!Number.isInteger(parsedMaxOpen) || parsedMaxOpen < 1) return { closedCount: 0, closedLsids: [] };

  const keepId = String(keepLsid || '').trim();
  const allowedOthers = keepId ? Math.max(parsedMaxOpen - 1, 0) : parsedMaxOpen;

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const openSessionsResult = await client.query(
      `SELECT id
       FROM login_sessions
       WHERE user_id = $1
         AND consumed_at IS NULL
         AND ($2 = '' OR id::text <> $2)
       ORDER BY created_at ASC, id ASC
       FOR UPDATE`,
      [parsedUserId, keepId]
    );

    const openSessionIds = openSessionsResult.rows.map((row) => row.id);
    const overflow = openSessionIds.length - allowedOthers;
    if (overflow <= 0) {
      await client.query('COMMIT');
      return { closedCount: 0, closedLsids: [] };
    }

    const idsToClose = openSessionIds.slice(0, overflow);
    const closeResult = await client.query(
      `UPDATE login_sessions
       SET consumed_at = NOW(),
           status = 'CLOSED',
           closed_at = COALESCE(closed_at, NOW())
       WHERE id = ANY($1::uuid[])
         AND ($2 = '' OR id::text <> $2)
       RETURNING id`,
      [idsToClose, keepId]
    );

    await client.query('COMMIT');

    logInfo('session_cleanup_enforced', {
      user_id: parsedUserId,
      keep_lsid: keepId || null,
      max_open: parsedMaxOpen,
      closed_count: closeResult.rowCount
    });

    return { closedCount: closeResult.rowCount, closedLsids: closeResult.rows.map((row) => row.id) };
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

async function closeStaleAuthorizedOpenSessions(maxAgeHours = 24) {
  const parsedMaxAgeHours = Number(maxAgeHours);
  if (!Number.isFinite(parsedMaxAgeHours) || parsedMaxAgeHours <= 0) return { closedCount: 0 };

  try {
    const result = await pool.query(
      `UPDATE login_sessions
       SET consumed_at = NOW(),
           status = 'CLOSED',
           closed_at = COALESCE(closed_at, NOW())
       WHERE consumed_at IS NULL
         AND authorized_at IS NOT NULL
         AND authorized_at < NOW() - ($1::int * INTERVAL '1 hour')`,
      [Math.floor(parsedMaxAgeHours)]
    );

    if (result.rowCount > 0) {
      logInfo('session_cleanup_stale_authorized_closed', {
        max_age_hours: Math.floor(parsedMaxAgeHours),
        closed_count: result.rowCount
      });
    }

    return { closedCount: result.rowCount };
  } catch (error) {
    logError('session_cleanup_stale_authorized_failed', { error, max_age_hours: Math.floor(parsedMaxAgeHours) });
    return { closedCount: 0 };
  }
}

module.exports = { enforceMaxOpenSessions, closeStaleAuthorizedOpenSessions };
