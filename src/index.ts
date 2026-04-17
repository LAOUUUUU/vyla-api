// Vyla API Worker
//
// Routes:
//   GET  /api/config                  -> Supabase public config
//   POST /api/tmdb                    -> TMDB proxy (keeps the TMDB key server-side)
//   GET  /api/youtube                 -> YouTube trailer metadata stub
//   POST /api/auth?action=signup      -> { username, password, turnstileToken }
//   POST /api/auth?action=login       -> { username, password }
//   POST /api/auth?action=logout      -> fire-and-forget, best effort
//   POST /api/auth?action=refresh     -> { refreshToken }
//   GET  /api/auth?action=lists       -> Bearer — returns user's profile/lists
//   PUT  /api/auth?action=lists       -> Bearer — upserts lists/settings
//   POST /api/auth?action=update_profile -> Bearer — { username?, avatarUrl? }
//   POST /api/auth                    -> Bearer — body { action: 'update_role', ... } (admin)
//
// Secrets (set via `npx wrangler secret put <NAME>`):
//   SUPABASE_SERVICE_ROLE   — sb_secret_... (NEVER commit)
//   TURNSTILE_SECRET        — Cloudflare Turnstile secret key (NEVER commit)
//
// Public constants live inline — they'd be visible anyway via /api/config.

interface Env {
  SUPABASE_SERVICE_ROLE: string;
  TURNSTILE_SECRET: string;
}

const SUPABASE_URL = 'https://nvnmoqghldbbhtycpjtx.supabase.co';
const SUPABASE_ANON_KEY = 'sb_publishable_kaP-pzvMjdUmwn681vovDg_D67UE9u_';

// Synthesized email domain — users sign in with just a username, we shape an
// email behind the scenes because Supabase Auth is email-based.
const EMAIL_DOMAIN = 'vyla.local';

const ALLOWED_ORIGINS = [
  'https://vyla.pages.dev',
  'https://vyla.laodebeqirize.workers.dev',
  'http://localhost:8000',
  'http://localhost:3000',
  'http://127.0.0.1:8000',
  'http://127.0.0.1:3000',
];

const USERNAME_RE = /^[a-zA-Z0-9_]{3,24}$/;

// ─── helpers ────────────────────────────────────────────────────────────────

function corsHeaders(origin: string): Record<string, string> {
  const allowed = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
  return {
    'Access-Control-Allow-Origin': allowed,
    'Access-Control-Allow-Methods': 'GET, POST, PUT, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Vary': 'Origin',
    'Content-Type': 'application/json',
  };
}

function json(data: unknown, status: number, headers: Record<string, string>): Response {
  return new Response(JSON.stringify(data), { status, headers });
}

function usernameToEmail(username: string): string {
  return `${username.toLowerCase()}@${EMAIL_DOMAIN}`;
}

async function verifyTurnstile(token: string, secret: string, ip: string | null): Promise<boolean> {
  if (!token) return false;
  const form = new URLSearchParams();
  form.append('secret', secret);
  form.append('response', token);
  if (ip) form.append('remoteip', ip);
  try {
    const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      body: form,
    });
    const data = await r.json() as { success?: boolean };
    return !!data.success;
  } catch {
    return false;
  }
}

// Direct calls to Supabase Admin API via service role.
// Auth docs: https://supabase.com/docs/reference/auth
async function supaAdmin(
  path: string,
  init: RequestInit,
  serviceRole: string
): Promise<Response> {
  return fetch(`${SUPABASE_URL}${path}`, {
    ...init,
    headers: {
      'apikey': serviceRole,
      'Authorization': `Bearer ${serviceRole}`,
      'Content-Type': 'application/json',
      ...(init.headers || {}),
    },
  });
}

async function supaAnon(path: string, init: RequestInit): Promise<Response> {
  return fetch(`${SUPABASE_URL}${path}`, {
    ...init,
    headers: {
      'apikey': SUPABASE_ANON_KEY,
      'Content-Type': 'application/json',
      ...(init.headers || {}),
    },
  });
}

async function getProfile(userId: string, serviceRole: string) {
  const r = await supaAdmin(
    `/rest/v1/profiles?id=eq.${userId}&select=*`,
    { method: 'GET' },
    serviceRole
  );
  if (!r.ok) return null;
  const rows = await r.json() as any[];
  return rows[0] ?? null;
}

async function getUserFromAccessToken(accessToken: string): Promise<{ id: string } | null> {
  // /auth/v1/user validates the JWT for us — cheaper than decoding ourselves
  // and tolerant of key rotations.
  const r = await fetch(`${SUPABASE_URL}/auth/v1/user`, {
    headers: {
      'apikey': SUPABASE_ANON_KEY,
      'Authorization': `Bearer ${accessToken}`,
    },
  });
  if (!r.ok) return null;
  const data = await r.json() as { id?: string };
  return data.id ? { id: data.id } : null;
}

function loginResponseFromSession(profile: any, session: any) {
  return {
    id: profile.id,
    username: profile.username,
    role: profile.role || 'user',
    avatar_url: profile.avatar_url || null,
    session,
  };
}

// Normalize incoming list items to storage shape (snake_case).
function normalizeListItem(item: any) {
  if (!item || typeof item !== 'object') return null;
  // Accept either camelCase (frontend) or snake_case (already-normalized)
  const media_id = String(item.media_id ?? item.id ?? '');
  const media_type = String(item.media_type ?? item.type ?? '');
  if (!media_id || !media_type) return null;
  const date_added = item.date_added
    ? new Date(item.date_added).toISOString()
    : item.dateAdded
    ? new Date(item.dateAdded).toISOString()
    : new Date().toISOString();
  return {
    media_id,
    media_type,
    title: item.title ?? null,
    poster_path: item.poster_path ?? null,
    release_date: item.release_date ?? null,
    date_added,
  };
}

// ─── request router ─────────────────────────────────────────────────────────

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const pathname = url.pathname;
    const origin = request.headers.get('origin') || '';
    const headers = corsHeaders(origin);
    const ip = request.headers.get('cf-connecting-ip');

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers });
    }

    // ── /api/config ────────────────────────────────────────────────────────
    if (pathname === '/api/config') {
      return json({
        supabaseUrl: SUPABASE_URL,
        supabaseAnonKey: SUPABASE_ANON_KEY,
      }, 200, headers);
    }

    // ── /api/tmdb ──────────────────────────────────────────────────────────
    if (pathname === '/api/tmdb' && request.method === 'POST') {
      try {
        const body = await request.json() as { endpoint: string; params?: Record<string, any> };
        const { endpoint, params } = body;
        const tmdbApiKey = '9c7900ddd0ede2e21e8ac5725e7efc28';
        const qp = new URLSearchParams();
        qp.append('api_key', tmdbApiKey);
        if (params) for (const [k, v] of Object.entries(params)) qp.append(k, String(v));
        const r = await fetch(`https://api.themoviedb.org/3${endpoint}?${qp.toString()}`);
        if (!r.ok) throw new Error(`TMDB API error: ${r.status}`);
        return new Response(r.body, { status: 200, headers });
      } catch (e: any) {
        return json({ error: e.message }, 500, headers);
      }
    }

    // ── /api/youtube ───────────────────────────────────────────────────────
    if (pathname === '/api/youtube') {
      const id = url.searchParams.get('id');
      if (!id) return json({ error: 'Missing video ID' }, 400, headers);
      return json({ title: 'Trailer', uploader: 'YouTube' }, 200, headers);
    }

    // ── /api/auth ──────────────────────────────────────────────────────────
    if (pathname === '/api/auth') {
      const action = url.searchParams.get('action') || '';
      try {
        // POST /api/auth?action=signup ───────────────────────────────────
        if (action === 'signup' && request.method === 'POST') {
          const { username, password, turnstileToken } = await request.json() as any;

          if (!USERNAME_RE.test(username || '')) {
            return json({ message: 'Username must be 3–24 characters, letters/numbers/underscore only.' }, 400, headers);
          }
          if (!password || password.length < 6) {
            return json({ message: 'Password must be at least 6 characters.' }, 400, headers);
          }

          // Turnstile check (bypass for local dev tokens Cloudflare provides)
          const isDevToken = turnstileToken === 'XXXX.DUMMY.TOKEN.XXXX';
          if (!isDevToken) {
            const ok = await verifyTurnstile(turnstileToken, env.TURNSTILE_SECRET, ip);
            if (!ok) return json({ message: 'Captcha verification failed. Please try again.' }, 403, headers);
          }

          // Username availability check
          const existing = await supaAdmin(
            `/rest/v1/profiles?username=eq.${encodeURIComponent(username.toLowerCase())}&select=id`,
            { method: 'GET' },
            env.SUPABASE_SERVICE_ROLE
          );
          const existingRows = existing.ok ? await existing.json() as any[] : [];
          if (existingRows.length > 0) {
            return json({ message: 'That username is taken.' }, 409, headers);
          }

          // Create auth user (admin API bypasses email confirmation)
          const email = usernameToEmail(username);
          const createResp = await supaAdmin(
            '/auth/v1/admin/users',
            {
              method: 'POST',
              body: JSON.stringify({
                email,
                password,
                email_confirm: true,
                user_metadata: { username: username.toLowerCase() },
              }),
            },
            env.SUPABASE_SERVICE_ROLE
          );
          if (!createResp.ok) {
            const err = await createResp.json().catch(() => ({})) as any;
            return json({ message: err.msg || err.message || 'Signup failed.' }, 400, headers);
          }
          const created = await createResp.json() as { id: string };

          // Insert profile row
          const profileResp = await supaAdmin(
            '/rest/v1/profiles',
            {
              method: 'POST',
              headers: { 'Prefer': 'return=representation' },
              body: JSON.stringify({
                id: created.id,
                username: username.toLowerCase(),
                role: 'user',
                settings: {},
                favorites: [],
                watch_later: [],
                watch_progress: {},
              }),
            },
            env.SUPABASE_SERVICE_ROLE
          );
          if (!profileResp.ok) {
            // Roll back: delete the auth user we just created so this
            // username can be retried without collision.
            await supaAdmin(`/auth/v1/admin/users/${created.id}`, { method: 'DELETE' }, env.SUPABASE_SERVICE_ROLE).catch(() => {});
            const err = await profileResp.json().catch(() => ({})) as any;
            return json({ message: err.message || 'Profile creation failed.' }, 500, headers);
          }

          return json({ id: created.id, username: username.toLowerCase() }, 200, headers);
        }

        // POST /api/auth?action=login ────────────────────────────────────
        if (action === 'login' && request.method === 'POST') {
          const { username, password } = await request.json() as any;
          if (!username || !password) {
            return json({ message: 'Username and password required.' }, 400, headers);
          }

          const email = usernameToEmail(username);
          const tokenResp = await supaAnon('/auth/v1/token?grant_type=password', {
            method: 'POST',
            body: JSON.stringify({ email, password }),
          });

          if (!tokenResp.ok) {
            return json({ message: 'Invalid username or password.' }, 401, headers);
          }
          const session = await tokenResp.json() as any;

          const profile = await getProfile(session.user.id, env.SUPABASE_SERVICE_ROLE);
          if (!profile) {
            return json({ message: 'Profile missing. Contact support.' }, 500, headers);
          }

          return json(loginResponseFromSession(profile, session), 200, headers);
        }

        // POST /api/auth?action=logout ───────────────────────────────────
        if (action === 'logout' && request.method === 'POST') {
          const authz = request.headers.get('authorization') || '';
          const token = authz.startsWith('Bearer ') ? authz.slice(7) : '';
          if (token) {
            await fetch(`${SUPABASE_URL}/auth/v1/logout`, {
              method: 'POST',
              headers: {
                'apikey': SUPABASE_ANON_KEY,
                'Authorization': `Bearer ${token}`,
              },
            }).catch(() => {});
          }
          return json({ ok: true }, 200, headers);
        }

        // POST /api/auth?action=refresh ──────────────────────────────────
        if (action === 'refresh' && request.method === 'POST') {
          const { refreshToken } = await request.json() as any;
          if (!refreshToken) {
            return json({ message: 'Missing refresh token.' }, 400, headers);
          }
          const r = await supaAnon('/auth/v1/token?grant_type=refresh_token', {
            method: 'POST',
            body: JSON.stringify({ refresh_token: refreshToken }),
          });
          if (!r.ok) {
            return json({ message: 'Refresh failed.' }, 401, headers);
          }
          const session = await r.json() as any;
          const profile = await getProfile(session.user.id, env.SUPABASE_SERVICE_ROLE);
          if (!profile) {
            return json({ message: 'Profile missing.' }, 500, headers);
          }
          return json(loginResponseFromSession(profile, session), 200, headers);
        }

        // From here on we require a Bearer token ─────────────────────────
        const authz = request.headers.get('authorization') || '';
        const accessToken = authz.startsWith('Bearer ') ? authz.slice(7) : '';
        if (!accessToken) {
          return json({ message: 'Unauthorized.' }, 401, headers);
        }
        const authedUser = await getUserFromAccessToken(accessToken);
        if (!authedUser) {
          return json({ message: 'Invalid session.' }, 401, headers);
        }

        // GET /api/auth?action=lists ─────────────────────────────────────
        if (action === 'lists' && request.method === 'GET') {
          const profile = await getProfile(authedUser.id, env.SUPABASE_SERVICE_ROLE);
          if (!profile) return json({ message: 'Profile missing.' }, 500, headers);

          return json({
            favorites: profile.favorites || [],
            watchLater: profile.watch_later || [],
            watchProgress: profile.watch_progress || {},
            settings: profile.settings || {},
            role: profile.role || 'user',
            avatar_url: profile.avatar_url || null,
          }, 200, headers);
        }

        // PUT /api/auth?action=lists ─────────────────────────────────────
        if (action === 'lists' && request.method === 'PUT') {
          const body = await request.json() as any;
          const patch: Record<string, any> = { updated_at: new Date().toISOString() };
          if (Array.isArray(body.favorites)) {
            patch.favorites = body.favorites.map(normalizeListItem).filter(Boolean);
          }
          if (Array.isArray(body.watchLater)) {
            patch.watch_later = body.watchLater.map(normalizeListItem).filter(Boolean);
          }
          if (body.watchProgress && typeof body.watchProgress === 'object') {
            patch.watch_progress = body.watchProgress;
          }
          if (body.settings && typeof body.settings === 'object') {
            patch.settings = body.settings;
          }
          const r = await supaAdmin(
            `/rest/v1/profiles?id=eq.${authedUser.id}`,
            {
              method: 'PATCH',
              headers: { 'Prefer': 'return=representation' },
              body: JSON.stringify(patch),
            },
            env.SUPABASE_SERVICE_ROLE
          );
          if (!r.ok) {
            const err = await r.json().catch(() => ({})) as any;
            return json({ message: err.message || 'Save failed.' }, 500, headers);
          }
          const [updated] = await r.json() as any[];
          return json({
            settings: updated?.settings ?? {},
          }, 200, headers);
        }

        // POST /api/auth?action=update_profile ───────────────────────────
        if (action === 'update_profile' && request.method === 'POST') {
          const { username, avatarUrl } = await request.json() as any;
          const patch: Record<string, any> = { updated_at: new Date().toISOString() };
          if (typeof username === 'string' && username.length) {
            if (!USERNAME_RE.test(username)) {
              return json({ message: 'Invalid username format.' }, 400, headers);
            }
            // Check for conflict
            const clash = await supaAdmin(
              `/rest/v1/profiles?username=eq.${encodeURIComponent(username.toLowerCase())}&id=neq.${authedUser.id}&select=id`,
              { method: 'GET' },
              env.SUPABASE_SERVICE_ROLE
            );
            const rows = clash.ok ? await clash.json() as any[] : [];
            if (rows.length > 0) {
              return json({ message: 'That username is taken.' }, 409, headers);
            }
            patch.username = username.toLowerCase();
          }
          if (typeof avatarUrl === 'string') {
            patch.avatar_url = avatarUrl || null;
          }
          const r = await supaAdmin(
            `/rest/v1/profiles?id=eq.${authedUser.id}`,
            {
              method: 'PATCH',
              headers: { 'Prefer': 'return=representation' },
              body: JSON.stringify(patch),
            },
            env.SUPABASE_SERVICE_ROLE
          );
          if (!r.ok) {
            const err = await r.json().catch(() => ({})) as any;
            return json({ message: err.message || 'Update failed.' }, 500, headers);
          }
          return json({ ok: true }, 200, headers);
        }

        // POST /api/auth (no action param) — admin role update ───────────
        if (!action && request.method === 'POST') {
          const body = await request.json() as any;
          if (body.action === 'update_role') {
            const caller = await getProfile(authedUser.id, env.SUPABASE_SERVICE_ROLE);
            if (!caller || !['admin', 'owner'].includes(caller.role)) {
              return json({ message: 'Forbidden.' }, 403, headers);
            }
            const { targetUserId, newRole } = body;
            if (!['user', 'admin', 'owner'].includes(newRole)) {
              return json({ message: 'Invalid role.' }, 400, headers);
            }
            // Only owners can grant/revoke owner
            if (newRole === 'owner' && caller.role !== 'owner') {
              return json({ message: 'Only owners can assign owner role.' }, 403, headers);
            }
            const r = await supaAdmin(
              `/rest/v1/profiles?id=eq.${targetUserId}`,
              {
                method: 'PATCH',
                body: JSON.stringify({ role: newRole, updated_at: new Date().toISOString() }),
              },
              env.SUPABASE_SERVICE_ROLE
            );
            if (!r.ok) {
              return json({ message: 'Failed to update role.' }, 500, headers);
            }
            return json({ message: `Role updated to ${newRole}.` }, 200, headers);
          }
          return json({ message: 'Unknown action.' }, 400, headers);
        }

        return json({ message: `Unsupported ${request.method} /api/auth?action=${action}` }, 405, headers);
      } catch (e: any) {
        console.error('[/api/auth] error:', e);
        return json({ message: e.message || 'Internal error.' }, 500, headers);
      }
    }

    // ── /api/discord — stub (returns 401 so auth.js clears the token) ──
    if (pathname === '/api/discord') {
      return json({ error: 'Discord integration not configured.' }, 401, headers);
    }

    return json({ error: 'Not found' }, 404, headers);
  },
};
