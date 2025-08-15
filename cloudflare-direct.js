/**
 * FastMCP AWS SES Server - Direct Cloudflare Worker Implementation
 * 
 * This runs the ENTIRE FastMCP server directly in Cloudflare Worker.
 * No external server needed! Just deploy this worker and you're done.
 */

// AWS SES V2 API implementation for Cloudflare Workers
class AWSSESClient {
  constructor(region, accessKeyId, secretAccessKey) {
    this.region = region;
    this.accessKeyId = accessKeyId;
    this.secretAccessKey = secretAccessKey;
    this.service = 'sesv2';
    this.host = `email.${region}.amazonaws.com`;
  }

  async signRequest(method, path, headers, body) {
    const now = new Date();
    const dateStamp = now.toISOString().slice(0, 10).replace(/-/g, '');
    const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '');

    headers['host'] = this.host;
    headers['x-amz-date'] = amzDate;

    const canonicalHeaders = Object.keys(headers)
      .sort()
      .map(key => `${key.toLowerCase()}:${headers[key]}`)
      .join('\n') + '\n';

    const signedHeaders = Object.keys(headers)
      .sort()
      .map(key => key.toLowerCase())
      .join(';');

    const payloadHash = await this.sha256(body);
    
    const canonicalRequest = [
      method,
      path,
      '', // query string
      canonicalHeaders,
      signedHeaders,
      payloadHash
    ].join('\n');

    const algorithm = 'AWS4-HMAC-SHA256';
    const credentialScope = `${dateStamp}/${this.region}/${this.service}/aws4_request`;
    const stringToSign = [
      algorithm,
      amzDate,
      credentialScope,
      await this.sha256(canonicalRequest)
    ].join('\n');

    const signature = await this.getSignature(dateStamp, stringToSign);

    headers['authorization'] = `${algorithm} Credential=${this.accessKeyId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

    return headers;
  }

  async sha256(data) {
    const encoder = new TextEncoder();
    const hash = await crypto.subtle.digest('SHA-256', encoder.encode(data));
    return Array.from(new Uint8Array(hash))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  async hmac(key, data) {
    const encoder = new TextEncoder();
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      typeof key === 'string' ? encoder.encode(key) : key,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    return await crypto.subtle.sign('HMAC', cryptoKey, encoder.encode(data));
  }

  async getSignature(dateStamp, stringToSign) {
    const kDate = await this.hmac(`AWS4${this.secretAccessKey}`, dateStamp);
    const kRegion = await this.hmac(kDate, this.region);
    const kService = await this.hmac(kRegion, this.service);
    const kSigning = await this.hmac(kService, 'aws4_request');
    const signature = await this.hmac(kSigning, stringToSign);
    
    return Array.from(new Uint8Array(signature))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  async sendEmail(params) {
    const path = '/v2/email/outbound-emails';
    const body = JSON.stringify(params);
    const headers = {
      'Content-Type': 'application/json'
    };

    const signedHeaders = await this.signRequest('POST', path, headers, body);

    const response = await fetch(`https://${this.host}${path}`, {
      method: 'POST',
      headers: signedHeaders,
      body
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`AWS SES Error (${response.status}): ${error}`);
    }

    return await response.json();
  }

  async listEmailTemplates() {
    const path = '/v2/email/templates';
    const headers = {};

    const signedHeaders = await this.signRequest('GET', path, headers, '');

    const response = await fetch(`https://${this.host}${path}`, {
      method: 'GET',
      headers: signedHeaders
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`AWS SES Error (${response.status}): ${error}`);
    }

    return await response.json();
  }

  async createEmailTemplate(templateName, templateContent) {
    const path = '/v2/email/templates';
    const body = JSON.stringify({
      TemplateName: templateName,
      TemplateContent: templateContent
    });
    const headers = {
      'Content-Type': 'application/json'
    };

    const signedHeaders = await this.signRequest('POST', path, headers, body);

    const response = await fetch(`https://${this.host}${path}`, {
      method: 'POST',
      headers: signedHeaders,
      body
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`AWS SES Error (${response.status}): ${error}`);
    }

    return await response.json();
  }

  async getAccount() {
    const path = '/v2/email/account';
    const headers = {};

    const signedHeaders = await this.signRequest('GET', path, headers, '');

    const response = await fetch(`https://${this.host}${path}`, {
      method: 'GET',
      headers: signedHeaders
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`AWS SES Error (${response.status}): ${error}`);
    }

    return await response.json();
  }
}

// FastMCP-style tool implementations
const tools = {
  async send_email(params, env) {
    const { to, subject, body, from_email, is_html = true } = params;
    
    if (!to || !subject || !body) {
      throw new Error('Missing required fields: to, subject, body');
    }

    const client = new AWSSESClient(
      env.AWS_REGION || 'us-east-1',
      env.AWS_ACCESS_KEY_ID,
      env.AWS_SECRET_ACCESS_KEY
    );

    const content = {
      Simple: {
        Subject: { Data: subject, Charset: 'UTF-8' },
        Body: {}
      }
    };

    if (is_html) {
      content.Simple.Body.Html = { Data: body, Charset: 'UTF-8' };
    } else {
      content.Simple.Body.Text = { Data: body, Charset: 'UTF-8' };
    }

    const response = await client.sendEmail({
      FromEmailAddress: from_email || env.EMAIL_DEFAULT_FROM || 'noreply@example.com',
      Destination: { ToAddresses: Array.isArray(to) ? to : [to] },
      Content: content
    });

    return {
      success: true,
      message_id: response.MessageId,
      to: Array.isArray(to) ? to : [to],
      subject,
      provider: 'aws-ses-v2',
      region: env.AWS_REGION || 'us-east-1',
      timestamp: new Date().toISOString()
    };
  },

  async get_templates(params, env) {
    const client = new AWSSESClient(
      env.AWS_REGION || 'us-east-1',
      env.AWS_ACCESS_KEY_ID,
      env.AWS_SECRET_ACCESS_KEY
    );

    const response = await client.listEmailTemplates();

    const templates = (response.TemplatesMetadata || []).map(template => ({
      name: template.TemplateName,
      created_at: template.CreatedTimestamp,
      provider: 'aws-ses-v2'
    }));

    return {
      templates,
      count: templates.length,
      provider: 'aws-ses-v2',
      region: env.AWS_REGION || 'us-east-1',
      timestamp: new Date().toISOString()
    };
  },

  async create_template(params, env) {
    const { template_name, subject, html_body, text_body } = params;
    
    if (!template_name || !subject) {
      throw new Error('Missing required fields: template_name, subject');
    }

    const client = new AWSSESClient(
      env.AWS_REGION || 'us-east-1',
      env.AWS_ACCESS_KEY_ID,
      env.AWS_SECRET_ACCESS_KEY
    );

    const templateContent = { Subject: subject };
    if (html_body) templateContent.Html = html_body;
    if (text_body) templateContent.Text = text_body;

    await client.createEmailTemplate(template_name, templateContent);

    return {
      success: true,
      template_name,
      message: `Template '${template_name}' created successfully`,
      provider: 'aws-ses-v2',
      region: env.AWS_REGION || 'us-east-1',
      timestamp: new Date().toISOString()
    };
  },

  async get_sending_quota(params, env) {
    const client = new AWSSESClient(
      env.AWS_REGION || 'us-east-1',
      env.AWS_ACCESS_KEY_ID,
      env.AWS_SECRET_ACCESS_KEY
    );

    const response = await client.getAccount();
    const sendQuota = response.SendQuota || {};

    const maxSend = sendQuota.Max24HourSend || 0;
    const sentLast24h = sendQuota.SentLast24Hours || 0;

    return {
      max_24_hour_send: maxSend,
      max_send_rate: sendQuota.MaxSendRate || 0,
      sent_last_24_hours: sentLast24h,
      remaining_today: maxSend - sentLast24h,
      percentage_used: maxSend > 0 ? (sentLast24h / maxSend * 100) : 0,
      provider: 'aws-ses-v2',
      region: env.AWS_REGION || 'us-east-1',
      timestamp: new Date().toISOString()
    };
  },

  async health_check(params, env) {
    try {
      const client = new AWSSESClient(
        env.AWS_REGION || 'us-east-1',
        env.AWS_ACCESS_KEY_ID,
        env.AWS_SECRET_ACCESS_KEY
      );

      const account = await client.getAccount();

      return {
        status: 'healthy',
        aws_ses_connected: true,
        sending_enabled: account.SendingEnabled || false,
        production_access: account.ProductionAccessEnabled || false,
        provider: 'aws-ses-v2',
        region: env.AWS_REGION || 'us-east-1',
        fastmcp_version: '2.0',
        deployment: 'cloudflare-worker',
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      return {
        status: 'unhealthy',
        aws_ses_connected: false,
        error: error.message,
        provider: 'aws-ses-v2',
        region: env.AWS_REGION || 'us-east-1',
        fastmcp_version: '2.0',
        deployment: 'cloudflare-worker',
        timestamp: new Date().toISOString()
      };
    }
  }
};

// Main Cloudflare Worker handler
export default {
  async fetch(request, env, ctx) {
    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-API-Key',
          'Access-Control-Max-Age': '86400'
        }
      });
    }

    try {
      const url = new URL(request.url);
      const path = url.pathname;

      // Health check
      if (path === '/health') {
        const result = await tools.health_check({}, env);
        return jsonResponse(result);
      }

      // FastMCP tool endpoints
      if (path.startsWith('/tools/')) {
        const toolName = path.substring(7); // Remove '/tools/'
        
        if (!tools[toolName]) {
          return jsonResponse({ error: `Tool not found: ${toolName}` }, 404);
        }

        // Authentication check
        if (env.API_KEY) {
          const providedKey = request.headers.get('Authorization')?.replace('Bearer ', '') ||
                             request.headers.get('X-API-Key') ||
                             url.searchParams.get('api_key');

          if (!providedKey || providedKey !== env.API_KEY) {
            return jsonResponse({ error: 'Unauthorized', message: 'Valid API key required' }, 401);
          }
        }

        // Parse request body for POST/PUT
        let params = {};
        if (request.method === 'POST' || request.method === 'PUT') {
          const contentType = request.headers.get('content-type');
          if (contentType && contentType.includes('application/json')) {
            params = await request.json();
          }
        }

        // Execute tool
        const result = await tools[toolName](params, env);
        return jsonResponse(result);
      }

      // List available tools
      if (path === '/tools') {
        const toolList = Object.keys(tools).map(name => ({
          name,
          description: getToolDescription(name),
          methods: getToolMethods(name)
        }));

        return jsonResponse({
          tools: toolList,
          count: toolList.length,
          server: 'FastMCP AWS SES (Cloudflare Worker)',
          timestamp: new Date().toISOString()
        });
      }

      return jsonResponse({ error: 'Not Found', message: 'Invalid endpoint' }, 404);

    } catch (error) {
      console.error('Worker error:', error);
      return jsonResponse({
        error: 'Internal Server Error',
        message: error.message
      }, 500);
    }
  }
};

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-API-Key'
    }
  });
}

function getToolDescription(toolName) {
  const descriptions = {
    send_email: 'Send an email to one or more recipients',
    get_templates: 'List all available AWS SES email templates',
    create_template: 'Create a new AWS SES email template',
    get_sending_quota: 'Get AWS SES sending limits and usage',
    health_check: 'Check server health and AWS SES connectivity'
  };
  return descriptions[toolName] || 'AWS SES operation';
}

function getToolMethods(toolName) {
  const methods = {
    send_email: ['POST'],
    get_templates: ['GET'],
    create_template: ['POST'],
    get_sending_quota: ['GET'],
    health_check: ['GET']
  };
  return methods[toolName] || ['GET', 'POST'];
}

/**
 * Example Usage:
 * 
 * Deploy this worker to Cloudflare:
 * 1. wrangler deploy
 * 2. wrangler secret put AWS_ACCESS_KEY_ID
 * 3. wrangler secret put AWS_SECRET_ACCESS_KEY
 * 4. wrangler secret put EMAIL_DEFAULT_FROM
 * 5. wrangler secret put API_KEY (optional)
 * 
 * Then call your endpoints:
 * 
 * Health check:
 * GET https://your-worker.your-subdomain.workers.dev/health
 * 
 * Send email:
 * POST https://your-worker.your-subdomain.workers.dev/tools/send_email
 * Headers: Content-Type: application/json, X-API-Key: your-api-key
 * Body: {
 *   "to": ["user@example.com"],
 *   "subject": "Hello from Cloudflare!",
 *   "body": "<h1>This email was sent from a Cloudflare Worker!</h1>",
 *   "is_html": true
 * }
 * 
 * List tools:
 * GET https://your-worker.your-subdomain.workers.dev/tools
 */