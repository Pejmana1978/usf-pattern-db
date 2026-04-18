export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { email, password, full_name, role, created_by } = req.body;

  if (!email || !password || !full_name || !role) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  const SUPA_URL = 'https://doommgfawoqiptgqadwd.supabase.co';
  const SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;

  try {
    // Step 1: Create auth user via Supabase Admin API
    const authRes = await fetch(`${SUPA_URL}/auth/v1/admin/users`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'apikey': SERVICE_KEY,
        'Authorization': `Bearer ${SERVICE_KEY}`,
      },
      body: JSON.stringify({
        email,
        password,
        email_confirm: true,
      }),
    });

    const authData = await authRes.json();

    if (!authRes.ok) {
      return res.status(400).json({ error: authData.message || authData.msg || 'Failed to create auth user' });
    }

    const uid = authData.id;

    // Step 2: Insert into user_profiles
    const profileRes = await fetch(`${SUPA_URL}/rest/v1/user_profiles`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'apikey': SERVICE_KEY,
        'Authorization': `Bearer ${SERVICE_KEY}`,
        'Prefer': 'return=minimal',
      },
      body: JSON.stringify({
        id: uid,
        email,
        full_name,
        role,
        created_by,
      }),
    });

    if (!profileRes.ok) {
      const profileErr = await profileRes.json();
      // Rollback: delete the auth user we just created
      await fetch(`${SUPA_URL}/auth/v1/admin/users/${uid}`, {
        method: 'DELETE',
        headers: {
          'apikey': SERVICE_KEY,
          'Authorization': `Bearer ${SERVICE_KEY}`,
        },
      });
      return res.status(400).json({ error: profileErr.message || 'Failed to create user profile' });
    }

    return res.status(200).json({ success: true, uid });

  } catch (err) {
    return res.status(500).json({ error: err.message || 'Server error' });
  }
}
