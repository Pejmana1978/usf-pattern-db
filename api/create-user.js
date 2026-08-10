// Create a user — on behalf of a manager or admin.
//
// SECURITY: this endpoint holds the service key, which can do anything to the
// database. It previously trusted the request body completely: no sign-in was
// required, and `role` was taken as given. Anyone who knew the URL could POST
// to it and mint themselves an admin account on the Pattern Database — and
// through user_profiles, on CPIS too.
//
// So the caller is now identified from their own bearer token, checked against
// user_profiles, and held to the same rules the UI shows them:
//   · only a manager or admin may create anyone at all;
//   · a manager may not create an admin — that is the escalation path;
//   · `created_by` is taken from the token, never from the body.

const SUPA_URL = 'https://doommgfawoqiptgqadwd.supabase.co';
const ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImRvb21tZ2Zhd29xaXB0Z3FhZHdkIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzUyODgzNTEsImV4cCI6MjA5MDg2NDM1MX0.EAUUhtPoGlqDQSLlABMwc5DptBI7T5HCkqC';

const ROLE_LEVEL = { admin: 4, manager: 3, editor: 2, viewer: 1 };

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;
  if (!SERVICE_KEY) return res.status(500).json({ error: 'Server is not configured' });

  const { email, password, full_name, role } = req.body || {};

  if (!email || !password || !full_name || !role) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  if (!ROLE_LEVEL[role]) {
    return res.status(400).json({ error: 'Unknown role' });
  }
  if (String(password).length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
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
    // ── Who is calling? From their token, never from the body ─────────────
    const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
    if (!token) return res.status(401).json({ error: 'Not signed in' });

    const whoRes = await fetch(`${SUPA_URL}/auth/v1/user`, {
      headers: { apikey: ANON_KEY, Authorization: `Bearer ${token}` },
    });
    if (!whoRes.ok) return res.status(401).json({ error: 'Session is not valid' });
    const caller = await whoRes.json();
    if (!caller?.id) return res.status(401).json({ error: 'Session is not valid' });

    const [callerProfile] = await (await svc(
      `/rest/v1/user_profiles?id=eq.${caller.id}&select=role,archived_at`,
    )).json();
    if (!callerProfile || callerProfile.archived_at) {
      return res.status(403).json({ error: 'Your account cannot create users' });
    }
    if (!['manager', 'admin'].includes(callerProfile.role)) {
      return res.status(403).json({ error: 'Only a manager or admin can create users' });
    }
    // A manager creating an admin would be handing themselves a promotion by
    // proxy. Admins may create any role.
    if (callerProfile.role !== 'admin' && ROLE_LEVEL[role] >= ROLE_LEVEL.admin) {
      return res.status(403).json({ error: 'Only an admin can create an admin' });
    }

    // ── Create the login ──────────────────────────────────────────────────
    const authRes = await svc('/auth/v1/admin/users', {
      method: 'POST',
      body: JSON.stringify({ email, password, email_confirm: true }),
    });
    const authData = await authRes.json();
    if (!authRes.ok) {
      return res.status(400).json({ error: authData.message || authData.msg || 'Failed to create auth user' });
    }
    const uid = authData.id;

    // ── Create the profile ────────────────────────────────────────────────
    const profileRes = await svc('/rest/v1/user_profiles', {
      method: 'POST',
      headers: { Prefer: 'return=minimal' },
      // created_by comes from the verified token, not the request body.
      body: JSON.stringify({ id: uid, email, full_name, role, created_by: caller.id }),
    });

    if (!profileRes.ok) {
      const profileErr = await profileRes.json().catch(() => ({}));
      // Roll back the login we just made, so a failure leaves nothing behind.
      await fetch(`${SUPA_URL}/auth/v1/admin/users/${uid}`, {
        method: 'DELETE',
        headers: { apikey: SERVICE_KEY, Authorization: `Bearer ${SERVICE_KEY}` },
      });
      return res.status(400).json({ error: profileErr.message || 'Failed to create user profile' });
    }

    return res.status(200).json({ success: true, uid });
  } catch (err) {
    return res.status(500).json({ error: err.message || 'Server error' });
  }
}
