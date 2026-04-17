export default {
  async fetch(request) {
    console.log('Worker received:', request.method, new URL(request.url).pathname);

    const url = new URL(request.url);
    const pathname = url.pathname;

    // Allowed origins for CORS
    const allowedOrigins = [
      'https://vyla.pages.dev',
      'https://vyla.laodebeqirize.workers.dev', 
      'http://localhost:8000',
      'http://localhost:3000',
      'http://127.0.0.1:8000',
      'http://127.0.0.1:3000'
    ];

    // Get origin from request and validate
    const origin = request.headers.get('origin') || '';
    const corsOrigin = allowedOrigins.includes(origin) ? origin : allowedOrigins[0];

    // CORS headers
    const headers = {
      'Access-Control-Allow-Origin': corsOrigin,
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Content-Type': 'application/json'
    };

    // Preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers });
    }

    // Config endpoint
    if (pathname === '/api/config') {
      return new Response(JSON.stringify({
        supabaseUrl: 'https://nvnmoqghldbbhtycpjtx.supabase.co',
        supabaseAnonKey: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im52bm1vcWdobGRiYmh0eWNwanR4Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzYwNDI1NTMsImV4cCI6MjA5MTYxODU1M30.74S57M72nXX5AGxJw3cT3iz8xb-3kqKXaewmBD5quRQ'
      }), { headers });
    }

    // TMDB proxy endpoint - proxies to real TMDB API
    if (pathname === '/api/tmdb') {
      try {
        const body = await request.json();
        const { endpoint, params } = body;

        // Build TMDB API URL
        const tmdbApiKey = '9c7900ddd0ede2e21e8ac5725e7efc28';
        const queryParams = new URLSearchParams();

        // Add API key
        queryParams.append('api_key', tmdbApiKey);

        // Add any additional params
        if (params) {
          for (const [key, value] of Object.entries(params)) {
            queryParams.append(key, String(value));
          }
        }

        const tmdbUrl = `https://api.themoviedb.org/3${endpoint}?${queryParams.toString()}`;
        const tmdbResponse = await fetch(tmdbUrl);

        if (!tmdbResponse.ok) {
          throw new Error(`TMDB API error: ${tmdbResponse.status}`);
        }

        const tmdbData = await tmdbResponse.json();

        return new Response(JSON.stringify(tmdbData), { headers });
      } catch (e) {
        return new Response(JSON.stringify({ error: e.message }), {
          status: 500,
          headers
        });
      }
    }

    // YouTube metadata endpoint
    if (pathname === '/api/youtube') {
      const videoId = url.searchParams.get('id');
      if (videoId) {
        return new Response(JSON.stringify({
          title: 'Trailer',
          uploader: 'YouTube'
        }), { headers });
      }
      return new Response(JSON.stringify({ error: 'Missing video ID' }), { status: 400, headers });
    }

    // Proxy to live API
    if (pathname.startsWith('/api/')) {
      try {
        const apiUrl = 'https://vyla-api.pages.dev' + pathname + url.search;
        const response = await fetch(apiUrl);

        // Copy upstream headers but exclude CORS headers to avoid duplication
        const proxyHeaders = {};
        for (const [key, value] of response.headers.entries()) {
          if (!key.toLowerCase().startsWith('access-control-')) {
            proxyHeaders[key] = value;
          }
        }

        return new Response(response.body, {
          status: response.status,
          headers: { ...proxyHeaders, ...headers }
        });
      } catch (e) {
        return new Response(JSON.stringify({ error: e.message }), {
          status: 500,
          headers
        });
      }
    }

    return new Response(JSON.stringify({ error: 'Not found' }), {
      status: 404,
      headers
    });
  }
};
