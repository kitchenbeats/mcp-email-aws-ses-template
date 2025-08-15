/**
 * Cloudflare Worker Proxy for FastMCP v2 AWS SES Server
 * 
 * This worker acts as a proxy between clients and your FastMCP server,
 * providing global edge distribution via Cloudflare's free tier.
 */

// Configuration - Set these in Cloudflare Worker environment variables
const FASTMCP_SERVER_URL = 'https://your-fastmcp-server.com'; // Your FastMCP server URL
const API_KEY = 'your-api-key'; // Optional API key for authentication

export default {
  async fetch(request, env, ctx) {
    // Handle CORS preflight requests
    if (request.method === 'OPTIONS') {
      return handleCORS();
    }

    try {
      // Extract the path and method
      const url = new URL(request.url);
      const path = url.pathname;
      const method = request.method;

      // Health check endpoint
      if (path === '/health' && method === 'GET') {
        return new Response(JSON.stringify({
          status: 'healthy',
          proxy: 'cloudflare-worker',
          timestamp: new Date().toISOString(),
          region: request.cf?.colo || 'unknown'
        }), {
          headers: {
            'Content-Type': 'application/json',
            ...getCORSHeaders()
          }
        });
      }

      // Validate API key if configured
      if (env.API_KEY || API_KEY) {
        const providedKey = request.headers.get('Authorization')?.replace('Bearer ', '') ||
                           request.headers.get('X-API-Key') ||
                           url.searchParams.get('api_key');

        if (!providedKey || providedKey !== (env.API_KEY || API_KEY)) {
          return new Response(JSON.stringify({
            error: 'Unauthorized',
            message: 'Valid API key required'
          }), {
            status: 401,
            headers: {
              'Content-Type': 'application/json',
              ...getCORSHeaders()
            }
          });
        }
      }

      // Forward request to FastMCP server
      const targetUrl = (env.FASTMCP_SERVER_URL || FASTMCP_SERVER_URL) + path + url.search;
      
      const proxyRequest = new Request(targetUrl, {
        method: request.method,
        headers: request.headers,
        body: request.body
      });

      // Remove Cloudflare-specific headers that might cause issues
      proxyRequest.headers.delete('cf-ray');
      proxyRequest.headers.delete('cf-connecting-ip');
      proxyRequest.headers.delete('cf-visitor');

      // Make request to FastMCP server
      const response = await fetch(proxyRequest);

      // Clone response and add CORS headers
      const modifiedResponse = new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: {
          ...Object.fromEntries(response.headers),
          ...getCORSHeaders()
        }
      });

      return modifiedResponse;

    } catch (error) {
      console.error('Proxy error:', error);
      
      return new Response(JSON.stringify({
        error: 'Proxy Error',
        message: 'Failed to connect to FastMCP server',
        details: error.message
      }), {
        status: 502,
        headers: {
          'Content-Type': 'application/json',
          ...getCORSHeaders()
        }
      });
    }
  }
};

function handleCORS() {
  return new Response(null, {
    status: 204,
    headers: getCORSHeaders()
  });
}

function getCORSHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-API-Key',
    'Access-Control-Max-Age': '86400'
  };
}

/**
 * Example FastMCP tool calls through this proxy:
 * 
 * POST https://your-worker.your-subdomain.workers.dev/tools/send_email
 * Headers: Content-Type: application/json, X-API-Key: your-api-key
 * Body: {
 *   "to": ["user@example.com"],
 *   "subject": "Test Email",
 *   "body": "Hello from Cloudflare + FastMCP!"
 * }
 * 
 * GET https://your-worker.your-subdomain.workers.dev/tools/get_templates
 * Headers: X-API-Key: your-api-key
 * 
 * POST https://your-worker.your-subdomain.workers.dev/tools/create_template
 * Headers: Content-Type: application/json, X-API-Key: your-api-key
 * Body: {
 *   "template_name": "welcome",
 *   "subject": "Welcome {{name}}!",
 *   "html_body": "<h1>Welcome {{name}}!</h1>"
 * }
 */