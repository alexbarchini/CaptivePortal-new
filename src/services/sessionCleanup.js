const { pool } = require('../db');
const { logError, logInfo } = require('../utils/logger');

async function enforceMaxOpenSessionsTx(client, userId, keepLsid, maxOpen = 5) {
  const parsedUserId = Number(userId);
  const parsedMaxOpen = Number(maxOpen);

  if (!Number.isInteger(parsedUserId) || parsedUserId <= 0) {
    return { enforced: false, closedSession: null, activeCountBefore: 0, activeCountAfter: 0 };
  }
  if (!Number.isInteger(parsedMaxOpen) || parsedMaxOpen < 1) {
    return { enforced: false, closedSession: null, activeCountBefore: 0, activeCountAfter: 0 };
  }

  const keepId = String(keepLsid || '').trim();

  const activeCountBeforeResult = await client.query(
    `SELECT COUNT(*)::int AS active_count
     FROM login_sessions
     WHERE user_id = $1
       AND status = 'OPEN'`,
    [parsedUserId]
  );
  const activeCountBefore = activeCountBeforeResult.rows[0]?.active_count || 0;

  if (activeCountBefore <= parsedMaxOpen) {
    return { enforced: false, closedSession: null, activeCountBefore, activeCountAfter: activeCountBefore };
  }

  const oldestOpenSessionResult = await client.query(
    `SELECT id, authorized_at
     FROM login_sessions
     WHERE user_id = $1
       AND status = 'OPEN'
       AND ($2 = '' OR id::text <> $2)
     ORDER BY authorized_at ASC NULLS LAST, created_at ASC, id ASC
     LIMIT 1
     FOR UPDATE`,
    [parsedUserId, keepId]
  );

  if (oldestOpenSessionResult.rowCount === 0) {
    return { enforced: false, closedSession: null, activeCountBefore, activeCountAfter: activeCountBefore };
  }

  const sessionToClose = oldestOpenSessionResult.rows[0];

  const closeResult = await client.query(
    `UPDATE login_sessions
     SET status = 'CLOSED',
         consumed_at = COALESCE(consumed_at, NOW()),
         closed_at = COALESCE(closed_at, NOW()),
         closed_reason = 'max_sessions_exceeded'
     WHERE id = $1
       AND status = 'OPEN'
       AND ($2 = '' OR id::text <> $2)
     RETURNING id, authorized_at`,
    [sessionToClose.id, keepId]
  );

  const activeCountAfterResult = await client.query(
    `SELECT COUNT(*)::int AS active_count
     FROM login_sessions
     WHERE user_id = $1
       AND status = 'OPEN'`,
    [parsedUserId]
  );

  const activeCountAfter = activeCountAfterResult.rows[0]?.active_count || 0;
  const closedSession = closeResult.rows[0] || null;

  return {
    enforced: closeResult.rowCount > 0,
    closedSession,
    activeCountBefore,
    activeCountAfter
  };
}

async function enforceMaxOpenSessions(userId, keepLsid, maxOpen = 5) {
  const client = await pool.connect();

  try {
    await client.query('BEGIN');
    await client.query('SELECT pg_advisory_xact_lock($1)', [Number(userId)]);
    const result = await enforceMaxOpenSessionsTx(client, userId, keepLsid, maxOpen);
    await client.query('COMMIT');

    if (result.enforced && result.closedSession) {
      logInfo('max_active_sessions_enforced', {
        user_id: Number(userId),
        new_session_id: keepLsid || null,
        closed_session_id: result.closedSession.id,
        closed_session_authorized_at: result.closedSession.authorized_at,
        active_count_before: result.activeCountBefore,
        active_count_after: result.activeCountAfter
      });
    }

    return result;
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

module.exports = { enforceMaxOpenSessions, enforceMaxOpenSessionsTx, closeStaleAuthorizedOpenSessions };
