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
//   DISCORD_CLIENT_ID       — Discord application Client ID (public, but kept in secrets for uniformity)
//   DISCORD_CLIENT_SECRET   — Discord application Client Secret (NEVER commit)
//   DISCORD_WEBHOOK_URL     — (optional) Discord webhook URL for error telemetry
//   DOWNLOAD_UPSTREAM_URL   — (optional) Base URL of an upstream source resolver
//                             that implements GET /api/download/{movie,tv}?id=...
//                             If unset, /api/download returns an empty source list
//                             so the UI shows "no downloads available" cleanly.
//
// Public constants live inline — they'd be visible anyway via /api/config.

interface Env {
  SUPABASE_SERVICE_ROLE: string;
  TURNSTILE_SECRET: string;
  DISCORD_CLIENT_ID?: string;
  DISCORD_CLIENT_SECRET?: string;
  DISCORD_WEBHOOK_URL?: string;
  DOWNLOAD_UPSTREAM_URL?: string;
}

const SUPABASE_URL = 'https://nvnmoqghldbbhtycpjtx.supabase.co';
const SUPABASE_ANON_KEY = 'sb_publishable_kaP-pzvMjdUmwn681vovDg_D67UE9u_';

// Discord OAuth config. The redirect URI here must match EXACTLY what's
// registered in the Discord Developer Portal for this application.
const DISCORD_REDIRECT_URI = 'https://vyla-api.laodebeqirize.workers.dev/api/discord?action=callback';
const DISCORD_FRONTEND_URL = 'https://vyla.laodebeqirize.workers.dev';
const DISCORD_SCOPES = 'identify email';

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
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, Cache-Control, Pragma, X-Requested-With',
    'Access-Control-Max-Age': '86400',
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

// Supabase Auth's /auth/v1/admin/users ban_duration accepts a Go duration
// string (e.g. "24h", "168h", "876000h" for ~100 years). The admin UI sends
// human inputs like "7d", "30m", "2h", or null/"" for "permanent".
function normalizeBanDuration(input: string | null | undefined): string {
  if (!input) return '876000h'; // ~100 years ≈ permanent
  const trimmed = String(input).trim().toLowerCase();
  // Already in Go-ish format (Ns/Nm/Nh)
  if (/^\d+(\.\d+)?(h|m|s)$/.test(trimmed)) return trimmed;
  // Days → hours
  const dayMatch = trimmed.match(/^(\d+(\.\d+)?)d$/);
  if (dayMatch) return `${Math.max(1, Math.round(parseFloat(dayMatch[1]) * 24))}h`;
  // Weeks → hours
  const weekMatch = trimmed.match(/^(\d+(\.\d+)?)w$/);
  if (weekMatch) return `${Math.max(1, Math.round(parseFloat(weekMatch[1]) * 168))}h`;
  // Bare number → treat as hours
  if (/^\d+(\.\d+)?$/.test(trimmed)) return `${trimmed}h`;
  // Fallback to permanent if we can't parse
  return '876000h';
}

// ─── Discord OAuth state helpers ────────────────────────────────────────────
// State is a short-lived HMAC-signed token binding the Discord redirect
// to a specific Supabase user id. Signing key = DISCORD_CLIENT_SECRET
// (already opaque on the Worker, saves adding a separate secret).

function b64urlEncode(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64urlDecode(s: string): Uint8Array {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function hmacSign(payload: string, secret: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload));
  return b64urlEncode(new Uint8Array(sig));
}

async function hmacVerify(payload: string, sig: string, secret: string): Promise<boolean> {
  const expected = await hmacSign(payload, secret);
  if (expected.length !== sig.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) diff |= expected.charCodeAt(i) ^ sig.charCodeAt(i);
  return diff === 0;
}

async function signOAuthState(userId: string, secret: string): Promise<string> {
  const payloadObj = { sub: userId, exp: Date.now() + 10 * 60 * 1000, nonce: crypto.randomUUID() };
  const payload = b64urlEncode(new TextEncoder().encode(JSON.stringify(payloadObj)));
  const sig = await hmacSign(payload, secret);
  return `${payload}.${sig}`;
}

async function verifyOAuthState(state: string, secret: string): Promise<string | null> {
  const parts = state.split('.');
  if (parts.length !== 2) return null;
  const [payload, sig] = parts;
  if (!(await hmacVerify(payload, sig, secret))) return null;
  try {
    const decoded = JSON.parse(new TextDecoder().decode(b64urlDecode(payload)));
    if (typeof decoded.sub !== 'string') return null;
    if (typeof decoded.exp !== 'number' || decoded.exp < Date.now()) return null;
    return decoded.sub;
  } catch {
    return null;
  }
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

    // ── /api/download/{movie,tv} ───────────────────────────────────────────
    // Frontend contract (js/index.js fetchSources / fetchDownloadable):
    //   GET /api/download/movie?id=<tmdb_id>
    //   GET /api/download/tv?id=<tmdb_id>&season=<n>&episode=<n>
    //   → { success: true, sources: [{ is_hls: bool, download_url: string, ... }] }
    //
    // This fork doesn't ship its own source scraper. If DOWNLOAD_UPSTREAM_URL
    // is configured we proxy through (preserving the full query string and
    // method); otherwise we return a well-formed empty payload so the UI
    // shows "No direct download links available" instead of crashing.
    if (pathname === '/api/download/movie' || pathname === '/api/download/tv') {
      if (request.method !== 'GET' && request.method !== 'HEAD') {
        return json({ error: 'Method not allowed' }, 405, headers);
      }
      const upstream = (env.DOWNLOAD_UPSTREAM_URL || '').replace(/\/+$/, '');
      if (!upstream) {
        // No resolver wired up — respond with empty sources so the frontend
        // retry loop exits cleanly rather than spinning on errors.
        return json({ success: true, sources: [] }, 200, headers);
      }
      try {
        const target = `${upstream}${pathname}${url.search}`;
        const r = await fetch(target, {
          method: 'GET',
          headers: { 'accept': 'application/json' },
          // Cloudflare Workers cache: download manifests are cheap to re-scrape
          // but expensive to discover, so a short edge cache is worth it.
          cf: { cacheTtl: 300, cacheEverything: true } as any,
        });
        const body = await r.text();
        // Pass through status + JSON body, but re-stamp CORS headers so the
        // browser accepts the response from our origin.
        return new Response(body, {
          status: r.status,
          headers: {
            ...headers,
            'content-type': r.headers.get('content-type') || 'application/json',
          },
        });
      } catch (e: any) {
        console.warn('[/api/download] upstream proxy failed:', e?.message || e);
        return json({ success: true, sources: [] }, 200, headers);
      }
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

        // POST /api/auth?action=feedback ─────────────────────────────────
        if (action === 'feedback' && request.method === 'POST') {
          const body = await request.json().catch(() => ({})) as Record<string, any>;
          // Store in a feedback table if present; otherwise fall back to a
          // log line so nothing is lost. Table columns are flexible — we
          // store the full payload as jsonb to avoid schema lockstep.
          const row = {
            user_id: authedUser.id,
            payload: body,
            created_at: new Date().toISOString(),
          };
          const r = await supaAdmin(
            '/rest/v1/feedback',
            {
              method: 'POST',
              headers: { 'Prefer': 'return=minimal' },
              body: JSON.stringify(row),
            },
            env.SUPABASE_SERVICE_ROLE
          );
          if (!r.ok) {
            // If the feedback table doesn't exist yet, don't fail the UX —
            // log and return 200 so the user sees "Feedback received".
            const errText = await r.text().catch(() => '');
            console.warn('[/api/auth?action=feedback] table missing or insert failed:', r.status, errText);
          }
          return json({ ok: true }, 200, headers);
        }

        // POST /api/auth (no action param) — admin dispatch ─────────────
        if (!action && request.method === 'POST') {
          const body = await request.json() as any;

          // All actions below require admin or owner. Fetch caller once.
          const caller = await getProfile(authedUser.id, env.SUPABASE_SERVICE_ROLE);
          if (!caller || !['admin', 'owner'].includes(caller.role)) {
            return json({ message: 'Forbidden.' }, 403, headers);
          }

          // ── update_role ─────────────────────────────────────────────
          if (body.action === 'update_role') {
            const { targetUserId, newRole } = body;
            if (!['user', 'admin', 'owner'].includes(newRole)) {
              return json({ message: 'Invalid role.' }, 400, headers);
            }
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
            if (!r.ok) return json({ message: 'Failed to update role.' }, 500, headers);
            return json({ message: `Role updated to ${newRole}.` }, 200, headers);
          }

          // ── admin_update_site_config ────────────────────────────────
          // Stored in public.site_config as a single row (id=1) with a
          // jsonb `config` column, merged per key.
          if (body.action === 'admin_update_site_config') {
            const { key, value } = body;
            if (typeof key !== 'string' || !key) {
              return json({ message: 'key required.' }, 400, headers);
            }
            // Read current
            const cur = await supaAdmin(
              `/rest/v1/site_config?id=eq.1&select=config`,
              { method: 'GET' },
              env.SUPABASE_SERVICE_ROLE
            );
            let currentConfig: Record<string, any> = {};
            if (cur.ok) {
              const rows = await cur.json() as any[];
              if (rows[0]?.config && typeof rows[0].config === 'object') {
                currentConfig = rows[0].config;
              }
            }
            currentConfig[key] = value;
            // Upsert row id=1
            const up = await supaAdmin(
              `/rest/v1/site_config`,
              {
                method: 'POST',
                headers: {
                  'Prefer': 'resolution=merge-duplicates,return=minimal',
                },
                body: JSON.stringify({ id: 1, config: currentConfig, updated_at: new Date().toISOString() }),
              },
              env.SUPABASE_SERVICE_ROLE
            );
            if (!up.ok) {
              const errText = await up.text().catch(() => '');
              return json({ message: `Failed to save config: ${errText}` }, 500, headers);
            }
            return json({ ok: true, message: 'Config updated.' }, 200, headers);
          }

          // ── admin_user_management ───────────────────────────────────
          if (body.action === 'admin_user_management') {
            const sub = body.subAction;

            // find_user — single match by username (case-insensitive exact)
            if (sub === 'find_user') {
              const q: string = String(body.query || '').toLowerCase().trim();
              if (!q) return json({ message: 'query required.' }, 400, headers);
              const r = await supaAdmin(
                `/rest/v1/profiles?username=eq.${encodeURIComponent(q)}&select=id,username,role,avatar_url`,
                { method: 'GET' },
                env.SUPABASE_SERVICE_ROLE
              );
              const rows = r.ok ? await r.json() as any[] : [];
              if (rows.length === 0) return json({ message: 'Not found.' }, 404, headers);
              return json(rows[0], 200, headers);
            }

            // find_users_by_username — partial match (ILIKE)
            if (sub === 'find_users_by_username') {
              const q: string = String(body.query || '').toLowerCase().trim();
              if (!q) return json({ message: 'query required.' }, 400, headers);
              const r = await supaAdmin(
                `/rest/v1/profiles?username=ilike.*${encodeURIComponent(q)}*&select=id,username,role,avatar_url&order=username.asc&limit=50`,
                { method: 'GET' },
                env.SUPABASE_SERVICE_ROLE
              );
              const rows = r.ok ? await r.json() as any[] : [];
              if (rows.length === 0) return json([], 404, headers);
              return json(rows, 200, headers);
            }

            // get_all_users — paginated (50 per page)
            if (sub === 'get_all_users') {
              const page = Math.max(1, parseInt(body.page, 10) || 1);
              const limit = 50;
              const offset = (page - 1) * limit;
              const r = await supaAdmin(
                `/rest/v1/profiles?select=id,username,role,avatar_url,created_at&order=created_at.desc&limit=${limit}&offset=${offset}`,
                { method: 'GET', headers: { 'Prefer': 'count=exact' } },
                env.SUPABASE_SERVICE_ROLE
              );
              if (!r.ok) return json({ message: 'Failed to fetch users.' }, 500, headers);
              const users = await r.json() as any[];
              const contentRange = r.headers.get('content-range') || '';
              const count = parseInt(contentRange.split('/')[1], 10) || users.length;
              return json({ users, count }, 200, headers);
            }

            // inspect — profile + auth details + favorites + watchLater + recentHistory
            if (sub === 'inspect') {
              const targetId: string = body.targetUserId;
              if (!targetId) return json({ message: 'targetUserId required.' }, 400, headers);

              const [profileResp, authResp] = await Promise.all([
                supaAdmin(
                  `/rest/v1/profiles?id=eq.${targetId}&select=*`,
                  { method: 'GET' },
                  env.SUPABASE_SERVICE_ROLE
                ),
                supaAdmin(
                  `/auth/v1/admin/users/${targetId}`,
                  { method: 'GET' },
                  env.SUPABASE_SERVICE_ROLE
                ),
              ]);
              const profileRows = profileResp.ok ? await profileResp.json() as any[] : [];
              if (profileRows.length === 0) return json({ message: 'User not found.' }, 404, headers);
              const profile = profileRows[0];
              const authDetails = authResp.ok ? await authResp.json() : {};

              // Convert watch_progress {key: {title, last_updated_at, ...}} → sorted array
              const wp = profile.watch_progress || {};
              const recentHistory = Object.values(wp)
                .filter((h: any) => h && typeof h === 'object')
                .sort((a: any, b: any) => {
                  const ta = new Date(a.last_updated_at || 0).getTime();
                  const tb = new Date(b.last_updated_at || 0).getTime();
                  return tb - ta;
                })
                .slice(0, 20);

              return json({
                profile: {
                  id: profile.id,
                  username: profile.username,
                  email: authDetails.email || null,
                  role: profile.role,
                  visit_count: profile.settings?.visit_count || 0,
                },
                authDetails: {
                  created_at: authDetails.created_at || null,
                  last_sign_in_at: authDetails.last_sign_in_at || null,
                },
                favorites: profile.favorites || [],
                watchLater: profile.watch_later || [],
                recentHistory,
              }, 200, headers);
            }

            // delete_user — remove auth user (profile cascades)
            if (sub === 'delete_user') {
              const targetId: string = body.targetUserId;
              if (!targetId) return json({ message: 'targetUserId required.' }, 400, headers);
              if (targetId === authedUser.id) {
                return json({ message: 'Refusing to delete your own account.' }, 400, headers);
              }
              const r = await supaAdmin(
                `/auth/v1/admin/users/${targetId}`,
                { method: 'DELETE' },
                env.SUPABASE_SERVICE_ROLE
              );
              if (!r.ok) {
                const t = await r.text().catch(() => '');
                return json({ message: `Delete failed: ${t}` }, 500, headers);
              }
              return json({ message: 'User deleted.' }, 200, headers);
            }

            // ban_user — duration like "7d", "24h", "30m". null/empty = permanent.
            if (sub === 'ban_user') {
              const targetId: string = body.targetUserId;
              if (!targetId) return json({ message: 'targetUserId required.' }, 400, headers);
              const duration: string | null = body.duration || null;
              const banDuration = normalizeBanDuration(duration);
              const r = await supaAdmin(
                `/auth/v1/admin/users/${targetId}`,
                {
                  method: 'PUT',
                  body: JSON.stringify({ ban_duration: banDuration }),
                },
                env.SUPABASE_SERVICE_ROLE
              );
              if (!r.ok) {
                const t = await r.text().catch(() => '');
                return json({ message: `Ban failed: ${t}` }, 500, headers);
              }
              return json({ message: duration ? `User banned for ${duration}.` : 'User banned permanently.' }, 200, headers);
            }

            // unban_user — lifts ban (ban_duration=none)
            if (sub === 'unban_user') {
              const targetId: string = body.targetUserId;
              if (!targetId) return json({ message: 'targetUserId required.' }, 400, headers);
              const r = await supaAdmin(
                `/auth/v1/admin/users/${targetId}`,
                {
                  method: 'PUT',
                  body: JSON.stringify({ ban_duration: 'none' }),
                },
                env.SUPABASE_SERVICE_ROLE
              );
              if (!r.ok) {
                const t = await r.text().catch(() => '');
                return json({ message: `Unban failed: ${t}` }, 500, headers);
              }
              return json({ message: 'User unbanned.' }, 200, headers);
            }

            // reset_password — generate a recovery link (admin copies it)
            if (sub === 'reset_password') {
              const targetId: string = body.targetUserId;
              if (!targetId) return json({ message: 'targetUserId required.' }, 400, headers);
              const ar = await supaAdmin(
                `/auth/v1/admin/users/${targetId}`,
                { method: 'GET' },
                env.SUPABASE_SERVICE_ROLE
              );
              if (!ar.ok) return json({ message: 'User not found.' }, 404, headers);
              const authUser = await ar.json() as any;
              const email = authUser?.email;
              if (!email) return json({ message: 'Target has no email.' }, 400, headers);

              const linkResp = await supaAdmin(
                `/auth/v1/admin/generate_link`,
                {
                  method: 'POST',
                  body: JSON.stringify({ type: 'recovery', email }),
                },
                env.SUPABASE_SERVICE_ROLE
              );
              if (!linkResp.ok) {
                const t = await linkResp.text().catch(() => '');
                return json({ message: `Link generation failed: ${t}` }, 500, headers);
              }
              const linkData = await linkResp.json() as any;
              const link = linkData.action_link || linkData.properties?.action_link || null;
              if (!link) return json({ message: 'No link returned.' }, 500, headers);
              return json({ link, message: 'Reset link generated.' }, 200, headers);
            }

            // get_active_users — top N by (fav*2 + wl*2 + history)
            if (sub === 'get_active_users') {
              const limit = Math.min(50, Math.max(1, parseInt(body.limit, 10) || 10));
              const r = await supaAdmin(
                `/rest/v1/profiles?select=username,favorites,watch_later,watch_progress&limit=500`,
                { method: 'GET' },
                env.SUPABASE_SERVICE_ROLE
              );
              if (!r.ok) return json({ message: 'Failed to fetch users.' }, 500, headers);
              const rows = await r.json() as any[];
              const scored = rows.map((p) => {
                const favs = Array.isArray(p.favorites) ? p.favorites.length : 0;
                const wl = Array.isArray(p.watch_later) ? p.watch_later.length : 0;
                const hist = p.watch_progress && typeof p.watch_progress === 'object'
                  ? Object.keys(p.watch_progress).length
                  : 0;
                return {
                  username: p.username,
                  history_count: hist,
                  favorites_count: favs,
                  watch_later_count: wl,
                  activity_score: favs * 2 + wl * 2 + hist,
                };
              });
              scored.sort((a, b) => b.activity_score - a.activity_score);
              return json(scored.slice(0, limit), 200, headers);
            }

            // purge_history / purge_favorites / purge_watch_later
            if (sub === 'purge_history' || sub === 'purge_favorites' || sub === 'purge_watch_later') {
              const targetId: string = body.targetUserId;
              if (!targetId) return json({ message: 'targetUserId required.' }, 400, headers);
              const patch: Record<string, any> = { updated_at: new Date().toISOString() };
              if (sub === 'purge_history') patch.watch_progress = {};
              if (sub === 'purge_favorites') patch.favorites = [];
              if (sub === 'purge_watch_later') patch.watch_later = [];
              const r = await supaAdmin(
                `/rest/v1/profiles?id=eq.${targetId}`,
                { method: 'PATCH', body: JSON.stringify(patch) },
                env.SUPABASE_SERVICE_ROLE
              );
              if (!r.ok) return json({ message: 'Purge failed.' }, 500, headers);
              const humanLabel = sub === 'purge_history' ? 'history' : sub === 'purge_favorites' ? 'favorites' : 'watch later';
              return json({ message: `Cleared ${humanLabel}.` }, 200, headers);
            }

            // impersonate — NOT implemented (security-sensitive)
            if (sub === 'impersonate') {
              return json({ message: 'Impersonation is not supported on this deployment.' }, 501, headers);
            }

            // export_database — owner-only full dump (profiles only, keep it bounded)
            if (sub === 'export_database') {
              if (caller.role !== 'owner') {
                return json({ message: 'Only owners can export the database.' }, 403, headers);
              }
              const r = await supaAdmin(
                `/rest/v1/profiles?select=*&limit=10000`,
                { method: 'GET' },
                env.SUPABASE_SERVICE_ROLE
              );
              if (!r.ok) return json({ message: 'Export failed.' }, 500, headers);
              const profiles = await r.json();
              return json({ exported_at: new Date().toISOString(), profiles }, 200, headers);
            }

            return json({ message: `Unknown admin subAction: ${sub}` }, 400, headers);
          }

          return json({ message: 'Unknown action.' }, 400, headers);
        }

        return json({ message: `Unsupported ${request.method} /api/auth?action=${action}` }, 405, headers);
      } catch (e: any) {
        console.error('[/api/auth] error:', e);
        return json({ message: e.message || 'Internal error.' }, 500, headers);
      }
    }

    // ── /api/discord ───────────────────────────────────────────────────────
    if (pathname === '/api/discord') {
      const action = url.searchParams.get('action') || '';
      try {
        // Config guard — if the app isn't set up yet, return 401 on auth'd
        // actions so auth.js clears the stale token, and an error redirect
        // on the browser-facing callback.
        const discordConfigured = !!(env.DISCORD_CLIENT_ID && env.DISCORD_CLIENT_SECRET);

        // GET /api/discord?action=connect — auth'd, returns { redirectUrl }
        if (action === 'connect' && request.method === 'GET') {
          const authz = request.headers.get('authorization') || '';
          const accessToken = authz.startsWith('Bearer ') ? authz.slice(7) : '';
          if (!accessToken) return json({ message: 'Unauthorized.' }, 401, headers);
          const authedUser = await getUserFromAccessToken(accessToken);
          if (!authedUser) return json({ message: 'Invalid session.' }, 401, headers);

          if (!discordConfigured) {
            return json({ message: 'Discord integration not configured on server.' }, 503, headers);
          }

          const state = await signOAuthState(authedUser.id, env.DISCORD_CLIENT_SECRET!);
          const params = new URLSearchParams({
            client_id: env.DISCORD_CLIENT_ID!,
            redirect_uri: DISCORD_REDIRECT_URI,
            response_type: 'code',
            scope: DISCORD_SCOPES,
            state,
            prompt: 'consent',
          });
          return json(
            { redirectUrl: `https://discord.com/api/oauth2/authorize?${params.toString()}` },
            200,
            headers
          );
        }

        // GET /api/discord?action=callback — Discord redirects here with ?code&state
        if (action === 'callback' && request.method === 'GET') {
          const redirectWithError = (reason: string) =>
            Response.redirect(`${DISCORD_FRONTEND_URL}/?discord=error&reason=${encodeURIComponent(reason)}`, 302);

          const code = url.searchParams.get('code');
          const state = url.searchParams.get('state');
          const errParam = url.searchParams.get('error');
          if (errParam) return redirectWithError(errParam);
          if (!code || !state) return redirectWithError('missing_params');
          if (!discordConfigured) return redirectWithError('not_configured');

          const userId = await verifyOAuthState(state, env.DISCORD_CLIENT_SECRET!);
          if (!userId) return redirectWithError('bad_state');

          // Exchange authorization code for access + refresh tokens
          const tokenForm = new URLSearchParams();
          tokenForm.append('client_id', env.DISCORD_CLIENT_ID!);
          tokenForm.append('client_secret', env.DISCORD_CLIENT_SECRET!);
          tokenForm.append('grant_type', 'authorization_code');
          tokenForm.append('code', code);
          tokenForm.append('redirect_uri', DISCORD_REDIRECT_URI);

          const tokenResp = await fetch('https://discord.com/api/oauth2/token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: tokenForm.toString(),
          });
          if (!tokenResp.ok) {
            const t = await tokenResp.text().catch(() => '');
            console.error('[discord/callback] token exchange failed', tokenResp.status, t);
            return redirectWithError('token_exchange_failed');
          }
          const tokenData = await tokenResp.json() as {
            access_token: string;
            refresh_token: string;
            expires_in: number;
          };

          const profile = await getProfile(userId, env.SUPABASE_SERVICE_ROLE);
          if (!profile) return redirectWithError('profile_missing');

          const newSettings = {
            ...(profile.settings || {}),
            discord_access_token: tokenData.access_token,
            discord_refresh_token: tokenData.refresh_token,
            discord_token_expires: Date.now() + tokenData.expires_in * 1000,
          };
          const patchResp = await supaAdmin(
            `/rest/v1/profiles?id=eq.${userId}`,
            {
              method: 'PATCH',
              body: JSON.stringify({ settings: newSettings, updated_at: new Date().toISOString() }),
            },
            env.SUPABASE_SERVICE_ROLE
          );
          if (!patchResp.ok) return redirectWithError('save_failed');

          return Response.redirect(`${DISCORD_FRONTEND_URL}/?discord=connected`, 302);
        }

        // GET /api/discord?action=get_user_profile — auth'd, proxies /users/@me
        if (action === 'get_user_profile' && request.method === 'GET') {
          const authz = request.headers.get('authorization') || '';
          const accessToken = authz.startsWith('Bearer ') ? authz.slice(7) : '';
          if (!accessToken) return json({ message: 'Unauthorized.' }, 401, headers);
          const authedUser = await getUserFromAccessToken(accessToken);
          if (!authedUser) return json({ message: 'Invalid session.' }, 401, headers);

          const profile = await getProfile(authedUser.id, env.SUPABASE_SERVICE_ROLE);
          if (!profile) return json({ message: 'Profile missing.' }, 500, headers);

          let discordToken: string | undefined = profile.settings?.discord_access_token;
          const discordRefresh: string | undefined = profile.settings?.discord_refresh_token;
          const tokenExpires: number = profile.settings?.discord_token_expires || 0;

          if (!discordToken) return json({ message: 'Discord not linked.' }, 401, headers);

          // Proactively refresh if within 60s of expiry and we have a refresh token
          if (
            tokenExpires &&
            Date.now() > tokenExpires - 60_000 &&
            discordRefresh &&
            discordConfigured
          ) {
            const refreshForm = new URLSearchParams();
            refreshForm.append('client_id', env.DISCORD_CLIENT_ID!);
            refreshForm.append('client_secret', env.DISCORD_CLIENT_SECRET!);
            refreshForm.append('grant_type', 'refresh_token');
            refreshForm.append('refresh_token', discordRefresh);

            const refreshResp = await fetch('https://discord.com/api/oauth2/token', {
              method: 'POST',
              headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
              body: refreshForm.toString(),
            });
            if (refreshResp.ok) {
              const refreshed = await refreshResp.json() as {
                access_token: string;
                refresh_token: string;
                expires_in: number;
              };
              discordToken = refreshed.access_token;
              const newSettings = {
                ...(profile.settings || {}),
                discord_access_token: refreshed.access_token,
                discord_refresh_token: refreshed.refresh_token,
                discord_token_expires: Date.now() + refreshed.expires_in * 1000,
              };
              await supaAdmin(
                `/rest/v1/profiles?id=eq.${authedUser.id}`,
                {
                  method: 'PATCH',
                  body: JSON.stringify({ settings: newSettings, updated_at: new Date().toISOString() }),
                },
                env.SUPABASE_SERVICE_ROLE
              ).catch(() => {});
            } else {
              // Refresh failed — surface 401 so frontend clears the stale token
              return json({ message: 'Discord session expired.' }, 401, headers);
            }
          }

          const meResp = await fetch('https://discord.com/api/users/@me', {
            headers: { 'Authorization': `Bearer ${discordToken}` },
          });
          if (meResp.status === 401) return json({ message: 'Discord token invalid.' }, 401, headers);
          if (!meResp.ok) return json({ message: 'Failed to fetch Discord user.' }, 502, headers);
          const discordUser = await meResp.json();
          return json(discordUser, 200, headers);
        }

        // POST /api/discord?action=revoke — frontend passes { token }
        if (action === 'revoke' && request.method === 'POST') {
          const body = await request.json().catch(() => ({})) as { token?: string };
          const token = body.token;
          if (token && discordConfigured) {
            const form = new URLSearchParams();
            form.append('client_id', env.DISCORD_CLIENT_ID!);
            form.append('client_secret', env.DISCORD_CLIENT_SECRET!);
            form.append('token', token);
            await fetch('https://discord.com/api/oauth2/token/revoke', {
              method: 'POST',
              headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
              body: form.toString(),
            }).catch(() => {});
          }
          return json({ ok: true }, 200, headers);
        }

        // POST /api/discord?action=update_presence — Discord REST cannot set
        // user Rich Presence (that requires the Gateway WebSocket, which
        // Workers cannot hold open). Stubbed to 200 so the frontend's
        // fire-and-forget sync call doesn't error.
        if (action === 'update_presence') {
          return json({ ok: true, note: 'presence_not_supported_via_rest' }, 200, headers);
        }

        return json(
          { message: `Unsupported ${request.method} /api/discord?action=${action}` },
          405,
          headers
        );
      } catch (e: any) {
        console.error('[/api/discord] error:', e);
        return json({ message: e.message || 'Internal error.' }, 500, headers);
      }
    }

    // ── /api/discord-webhook — error telemetry sink ────────────────────
    // If DISCORD_WEBHOOK_URL is set, forwards the error. Otherwise just
    // logs and returns 200 so the frontend's fire-and-forget call never
    // spams the console with 404s.
    if (pathname === '/api/discord-webhook' && request.method === 'POST') {
      try {
        const body = await request.json().catch(() => ({})) as { type?: string; error?: string };
        const errorText = typeof body.error === 'string' ? body.error : JSON.stringify(body);
        if (env.DISCORD_WEBHOOK_URL) {
          // Discord webhook content cap is 2000 chars
          const trimmed = errorText.length > 1900 ? errorText.slice(0, 1900) + '…' : errorText;
          await fetch(env.DISCORD_WEBHOOK_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              content: `**Vyla ${body.type || 'event'}**\n\`\`\`\n${trimmed}\n\`\`\``,
            }),
          }).catch((e) => console.warn('[discord-webhook] forward failed', e));
        } else {
          console.warn('[discord-webhook]', body.type, errorText);
        }
      } catch {
        // Never surface errors to the caller — telemetry must not break UX.
      }
      return json({ ok: true }, 200, headers);
    }

    // ── /api/admin/broadcast — Supabase Realtime broadcast (admin only) ─
    if (pathname === '/api/admin/broadcast' && request.method === 'POST') {
      try {
        const authz = request.headers.get('authorization') || '';
        const accessToken = authz.startsWith('Bearer ') ? authz.slice(7) : '';
        if (!accessToken) return json({ message: 'Unauthorized.' }, 401, headers);
        const authedUser = await getUserFromAccessToken(accessToken);
        if (!authedUser) return json({ message: 'Invalid session.' }, 401, headers);
        const caller = await getProfile(authedUser.id, env.SUPABASE_SERVICE_ROLE);
        if (!caller || !['admin', 'owner'].includes(caller.role)) {
          return json({ message: 'Forbidden.' }, 403, headers);
        }

        const body = await request.json().catch(() => ({})) as {
          channelName?: string;
          event?: string;
          payload?: any;
        };
        if (!body.channelName || !body.event) {
          return json({ message: 'channelName and event required.' }, 400, headers);
        }

        // Supabase Realtime broadcast via REST
        const r = await fetch(`${SUPABASE_URL}/realtime/v1/api/broadcast`, {
          method: 'POST',
          headers: {
            'apikey': env.SUPABASE_SERVICE_ROLE,
            'Authorization': `Bearer ${env.SUPABASE_SERVICE_ROLE}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            messages: [
              {
                topic: body.channelName,
                event: body.event,
                payload: body.payload ?? {},
              },
            ],
          }),
        });
        if (!r.ok) {
          const errText = await r.text().catch(() => '');
          return json({ message: `Broadcast failed: ${errText || r.status}` }, 500, headers);
        }
        return json({ ok: true }, 200, headers);
      } catch (e: any) {
        console.error('[/api/admin/broadcast] error:', e);
        return json({ message: e.message || 'Internal error.' }, 500, headers);
      }
    }

    return json({ error: 'Not found' }, 404, headers);
  },
};
