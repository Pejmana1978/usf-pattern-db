// Remove a person from the app — on behalf of a manager or admin.
//
// "Remove" here means archived and locked out, NOT deleted. That distinction is
// deliberate:
//
//   · patterns.created_by and four other columns are foreign keys into
//     user_profiles. Deleting the row is refused by Postgres, and forcing it
//     through would blank the creator on every pattern they built. The owner's
//     requirement is that their name STAYS on their patterns.
//   · So the profile row is kept and stamped archived_at. Attribution survives,
//     the foreign keys stay satisfied, and the user list simply hides them.
//   · Access is stopped in auth.users, which is a separate system with no
//     foreign key to user_profiles — deleting a profile never blocked a login.
//
// The service key can do anything, so the caller is authenticated and
// authorised HERE, from their own bearer token, before it is used. Do not copy
// create-user.js, which takes the caller's word for who they are.

const SUPA_URL = 'https://doommgfawoqiptgqadwd.supabase.co';
const ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImRvb21tZ2Zhd29xaXB0Z3FhZHdkIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzUyODgzNTEsImV4cCI6MjA5MDg2NDM1MX0.EAUUhtPoGlqDQSLlABMwc5DptBI7T5HCkqC';

/** 100 years. GoTrue takes a duration, not a date. 'none' lifts a ban. */
const FOREVER = '876000h';

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;
  if (!SERVICE_KEY) return res.status(500).json({ error: 'Server is not configured' });

  const { user_id: targetId, restore = false } = req.body || {};
  if (!targetId || !/^[0-9a-f-]{36}$/i.test(targetId)) {
    return res.status(400).json({ error: 'Missing or invalid user_id' });
  }

  const svc = (path, init = {}) => fetch(`${SUPA_URL}${path}`, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      apikey: SERVICE_KEY,
      Authorization: `Bearer ${SERVICE_KEY}`,
      ...(init.headers || {}),
    },
  });

  try {
    // ── 1. Who is calling? Taken from their token, never from the body ─────
    const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
    if (!token) return res.status(401).json({ error: 'Not signed in' });

    const whoRes = await fetch(`${SUPA_URL}/auth/v1/user`, {
      headers: { apikey: ANON_KEY, Authorization: `Bearer ${token}` },
    });
    if (!whoRes.ok) return res.status(401).json({ error: 'Session is not valid' });
    const caller = await whoRes.json();
    if (!caller?.id) return res.status(401).json({ error: 'Session is not valid' });

    // ── 2. Are they allowed to? ───────────────────────────────────────────
    const [callerProfile] = await (await svc(
      `/rest/v1/user_profiles?id=eq.${caller.id}&select=role`,
    )).json();
    if (!callerProfile || !['manager', 'admin'].includes(callerProfile.role)) {
      return res.status(403).json({ error: 'Only a manager or admin can remove users' });
    }

    const [target] = await (await svc(
      `/rest/v1/user_profiles?id=eq.${targetId}&select=role,full_name,email,archived_at`,
    )).json();
    if (!target) return res.status(404).json({ error: 'That user no longer exists' });
    const who = target.full_name || target.email;

    // ── 3. Restore is the same checks in reverse ──────────────────────────
    if (restore) {
      const un = await svc(`/rest/v1/user_profiles?id=eq.${targetId}`, {
        method: 'PATCH',
        body: JSON.stringify({ archived_at: null, archived_by: null }),
      });
      if (!un.ok) return res.status(400).json({ error: `Could not restore ${who}` });

      const unban = await svc(`/auth/v1/admin/users/${targetId}`, {
        method: 'PUT', body: JSON.stringify({ ban_duration: 'none' }),
      });
      if (!unban.ok && unban.status !== 404) {
        return res.status(400).json({ error: `${who} is back in the list, but the login is still blocked`, partial: true });
      }
      return res.status(200).json({ success: true, restored: who });
    }

    // ── 4. Guards ─────────────────────────────────────────────────────────
    if (targetId === caller.id) {
      return res.status(400).json({ error: 'You cannot remove your own account' });
    }
    // Never remove the last privileged account — that locks everyone out of
    // user management with no way back in through the app.
    if (['manager', 'admin'].includes(target.role)) {
      const others = await (await svc(
        '/rest/v1/user_profiles?role=in.(manager,admin)&archived_at=is.null&select=id',
      )).json();
      if (others.length <= 1) {
        return res.status(400).json({ error: 'This is the last active manager or admin and cannot be removed' });
      }
    }

    // ── 5. Release any edit locks, or their patterns stay frozen ──────────
    const unlock = await svc(`/rest/v1/patterns?locked_by=eq.${targetId}`, {
      method: 'PATCH',
      headers: { Prefer: 'return=representation' },
      body: JSON.stringify({ locked_by: null, locked_at: null }),
    });
    const locksReleased = unlock.ok ? (await unlock.json().catch(() => [])).length : 0;

    // ── 6. Archive the profile. The row STAYS so their name still resolves
    //       on everything they made. ──────────────────────────────────────
    const arch = await svc(`/rest/v1/user_profiles?id=eq.${targetId}`, {
      method: 'PATCH',
      body: JSON.stringify({ archived_at: new Date().toISOString(), archived_by: caller.id }),
    });
    if (!arch.ok) {
      const e = await arch.json().catch(() => ({}));
      return res.status(400).json({ error: e.message || `Could not archive ${who}` });
    }

    // ── 7. Stop the login. Separate system, so this is the step that
    //       actually removes access. ─────────────────────────────────────
    const ban = await svc(`/auth/v1/admin/users/${targetId}`, {
      method: 'PUT', body: JSON.stringify({ ban_duration: FOREVER }),
    });
    if (!ban.ok && ban.status !== 404) {
      const e = await ban.json().catch(() => ({}));
      return res.status(400).json({
        error: `${who} is out of the list, but the login could not be blocked: ${e.msg || e.message || ban.status}`,
        partial: true,
      });
    }

    return res.status(200).json({ success: true, removed: who, locksReleased });
  } catch (err) {
    return res.status(500).json({ error: err.message || 'Server error' });
  }
}
