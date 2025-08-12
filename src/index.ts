/**
 * MCP AWS SES Email Server - Cloudflare Worker
 * Fully compliant with Model Context Protocol JSON-RPC 2.0
 */

import { z } from 'zod';

// Environment interface
interface Env {
  AWS_ACCESS_KEY_ID: string;
  AWS_SECRET_ACCESS_KEY: string;
  AWS_REGION: string;
  EMAIL_DEFAULT_FROM?: string;
  MCP_PROTOCOL_VERSION: string;
  EMAIL_PROVIDER: string;
}

// MCP Protocol Types
interface JsonRpcRequest {
  jsonrpc: '2.0';
  method: string;
  params?: unknown;
  id: string | number | null;
}

interface JsonRpcResponse {
  jsonrpc: '2.0';
  result?: unknown;
  error?: JsonRpcError;
  id: string | number | null;
}

interface JsonRpcError {
  code: number;
  message: string;
  data?: unknown;
}

// Input validation schemas
const sendEmailSchema = z.object({
  to: z.array(z.string().email()),
  subject: z.string().min(1).max(500),
  body: z.string(),
  from: z.string().email().optional(),
  replyTo: z.string().email().optional(),
  isHtml: z.boolean().optional().default(true)
});

const sendBulkEmailSchema = z.object({
  recipients: z.array(z.object({
    email: z.string().email(),
    data: z.record(z.unknown()).optional()
  })),
  templateName: z.string(),
  globalData: z.record(z.unknown()).optional()
});

const getEmailStatusSchema = z.object({
  messageId: z.string().min(1)
});

// Available MCP tools
const TOOLS = [
  {
    name: 'send_email',
    description: 'Send an email to one or more recipients via AWS SES',
    inputSchema: {
      type: 'object',
      properties: {
        to: {
          type: 'array',
          items: { type: 'string' },
          description: 'Recipient email addresses'
        },
        subject: {
          type: 'string',
          description: 'Email subject line'
        },
        body: {
          type: 'string',
          description: 'Email body content (HTML or plain text)'
        },
        from: {
          type: 'string',
          description: 'Sender email address (optional, must be verified in SES)'
        },
        replyTo: {
          type: 'string',
          description: 'Reply-to email address (optional)'
        },
        isHtml: {
          type: 'boolean',
          description: 'Whether body contains HTML',
          default: true
        }
      },
      required: ['to', 'subject', 'body']
    }
  },
  {
    name: 'send_bulk_email',
    description: 'Send personalized emails to multiple recipients using AWS SES templates',
    inputSchema: {
      type: 'object',
      properties: {
        recipients: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              email: { type: 'string' },
              data: { type: 'object' }
            },
            required: ['email']
          },
          description: 'List of recipients with optional personalization data'
        },
        templateName: {
          type: 'string',
          description: 'AWS SES template name'
        },
        globalData: {
          type: 'object',
          description: 'Data available to all recipients'
        }
      },
      required: ['recipients', 'templateName']
    }
  },
  {
    name: 'get_templates',
    description: 'List available AWS SES email templates',
    inputSchema: {
      type: 'object',
      properties: {}
    }
  },
  {
    name: 'get_email_status',
    description: 'Check the delivery status of a sent email',
    inputSchema: {
      type: 'object',
      properties: {
        messageId: {
          type: 'string',
          description: 'Message ID returned from send operation'
        }
      },
      required: ['messageId']
    }
  }
];

// Main Worker handler
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type'
        }
      });
    }

    // Health check endpoint
    if (request.method === 'GET' && new URL(request.url).pathname === '/health') {
      return new Response(JSON.stringify({
        status: 'healthy',
        provider: env.EMAIL_PROVIDER,
        region: env.AWS_REGION,
        protocol: env.MCP_PROTOCOL_VERSION,
        timestamp: new Date().toISOString()
      }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // MCP requires POST
    if (request.method !== 'POST') {
      return createErrorResponse(null, -32600, 'Only POST method supported for MCP');
    }

    try {
      const body = await request.text();
      const rpcRequest: JsonRpcRequest = JSON.parse(body);

      // Validate JSON-RPC format
      if (rpcRequest.jsonrpc !== '2.0') {
        return createErrorResponse(rpcRequest.id, -32600, 'Must be JSON-RPC 2.0');
      }

      const response = await handleRpcMethod(rpcRequest, env);
      return new Response(JSON.stringify(response), {
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*'
        }
      });
    } catch (error) {
      return createErrorResponse(null, -32700, 'Parse error');
    }
  }
};

// MCP method router
async function handleRpcMethod(request: JsonRpcRequest, env: Env): Promise<JsonRpcResponse> {
  switch (request.method) {
    case 'initialize':
      return handleInitialize(request, env);
    
    case 'tools/list':
      return handleToolsList(request);
    
    case 'tools/call':
      return handleToolCall(request, env);
    
    default:
      return {
        jsonrpc: '2.0',
        error: {
          code: -32601,
          message: `Method not found: ${request.method}`
        },
        id: request.id
      };
  }
}

// Handle MCP initialize
function handleInitialize(request: JsonRpcRequest, env: Env): JsonRpcResponse {
  return {
    jsonrpc: '2.0',
    result: {
      protocolVersion: env.MCP_PROTOCOL_VERSION,
      capabilities: {
        tools: true,
        resources: false
      },
      serverInfo: {
        name: 'AWS SES Email MCP Server',
        version: '1.0.0'
      }
    },
    id: request.id
  };
}

// Handle tools list
function handleToolsList(request: JsonRpcRequest): JsonRpcResponse {
  return {
    jsonrpc: '2.0',
    result: { tools: TOOLS },
    id: request.id
  };
}

// Handle tool execution
async function handleToolCall(request: JsonRpcRequest, env: Env): Promise<JsonRpcResponse> {
  const params = request.params as { name: string; arguments: unknown };
  
  if (!params?.name) {
    return {
      jsonrpc: '2.0',
      error: {
        code: -32602,
        message: 'Invalid params - tool name required'
      },
      id: request.id
    };
  }

  try {
    let result: unknown;
    
    switch (params.name) {
      case 'send_email':
        result = await sendEmail(params.arguments, env);
        break;
      
      case 'send_bulk_email':
        result = await sendBulkEmail(params.arguments, env);
        break;
      
      case 'get_templates':
        result = await getTemplates(env);
        break;
      
      case 'get_email_status':
        result = await getEmailStatus(params.arguments, env);
        break;
      
      default:
        return {
          jsonrpc: '2.0',
          error: {
            code: -32601,
            message: `Tool not found: ${params.name}`
          },
          id: request.id
        };
    }

    return {
      jsonrpc: '2.0',
      result: {
        content: [
          {
            type: 'text',
            text: typeof result === 'string' ? result : JSON.stringify(result, null, 2)
          }
        ]
      },
      id: request.id
    };

  } catch (error) {
    return {
      jsonrpc: '2.0',
      error: {
        code: -32603,
        message: error instanceof Error ? error.message : 'Tool execution failed'
      },
      id: request.id
    };
  }
}

// AWS SES API signing helper
async function signAwsRequest(
  method: string,
  url: string,
  headers: Record<string, string>,
  body: string,
  env: Env
): Promise<Record<string, string>> {
  const host = new URL(url).host;
  const timestamp = new Date().toISOString().replace(/[:\-]|\.\d{3}/g, '');
  const date = timestamp.substring(0, 8);
  
  // Create canonical request
  const canonicalHeaders = Object.keys(headers)
    .sort()
    .map(key => `${key.toLowerCase()}:${headers[key]}`)
    .join('\n');
  
  const signedHeaders = Object.keys(headers)
    .sort()
    .map(key => key.toLowerCase())
    .join(';');
  
  const hashedPayload = await sha256(body);
  
  const canonicalRequest = [
    method,
    new URL(url).pathname,
    new URL(url).search.substring(1),
    canonicalHeaders,
    '',
    signedHeaders,
    hashedPayload
  ].join('\n');
  
  // Create string to sign
  const credentialScope = `${date}/${env.AWS_REGION}/ses/aws4_request`;
  const stringToSign = [
    'AWS4-HMAC-SHA256',
    timestamp,
    credentialScope,
    await sha256(canonicalRequest)
  ].join('\n');
  
  // Calculate signature
  const signingKey = await getSignatureKey(env.AWS_SECRET_ACCESS_KEY, date, env.AWS_REGION, 'ses');
  const signature = await hmacSha256(signingKey, stringToSign);
  
  // Create authorization header
  const authorization = `AWS4-HMAC-SHA256 Credential=${env.AWS_ACCESS_KEY_ID}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
  
  return {
    ...headers,
    'Authorization': authorization,
    'X-Amz-Date': timestamp
  };
}

// Crypto helpers
async function sha256(data: string): Promise<string> {
  const encoder = new TextEncoder();
  const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(data));
  return Array.from(new Uint8Array(hashBuffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

async function hmacSha256(key: ArrayBuffer, data: string): Promise<string> {
  const encoder = new TextEncoder();
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    key,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const signature = await crypto.subtle.sign('HMAC', cryptoKey, encoder.encode(data));
  return Array.from(new Uint8Array(signature))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

async function getSignatureKey(key: string, date: string, region: string, service: string): Promise<ArrayBuffer> {
  const encoder = new TextEncoder();
  const kDate = await hmacSha256Raw(encoder.encode(`AWS4${key}`), date);
  const kRegion = await hmacSha256Raw(kDate, region);
  const kService = await hmacSha256Raw(kRegion, service);
  return await hmacSha256Raw(kService, 'aws4_request');
}

async function hmacSha256Raw(key: ArrayBuffer, data: string): Promise<ArrayBuffer> {
  const encoder = new TextEncoder();
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    key,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  return await crypto.subtle.sign('HMAC', cryptoKey, encoder.encode(data));
}

// Send single email via AWS SES
async function sendEmail(args: unknown, env: Env): Promise<unknown> {
  const validated = sendEmailSchema.parse(args);
  const fromEmail = validated.from || env.EMAIL_DEFAULT_FROM || 'noreply@example.com';
  
  const params = new URLSearchParams({
    'Action': 'SendEmail',
    'Source': fromEmail,
    'Message.Subject.Data': validated.subject,
    'Message.Body.Html.Data': validated.isHtml ? validated.body : '',
    'Message.Body.Text.Data': validated.isHtml ? '' : validated.body,
    'Version': '2010-12-01'
  });
  
  // Add destinations
  validated.to.forEach((email, index) => {
    params.append(`Destination.ToAddresses.member.${index + 1}`, email);
  });
  
  if (validated.replyTo) {
    params.append('ReplyToAddresses.member.1', validated.replyTo);
  }
  
  const url = `https://ses.${env.AWS_REGION}.amazonaws.com`;
  const body = params.toString();
  
  const headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    'Host': `ses.${env.AWS_REGION}.amazonaws.com`
  };
  
  const signedHeaders = await signAwsRequest('POST', url, headers, body, env);
  
  const response = await fetch(url, {
    method: 'POST',
    headers: signedHeaders,
    body
  });
  
  if (!response.ok) {
    const error = await response.text();
    throw new Error(`AWS SES API error: ${error}`);
  }
  
  const responseText = await response.text();
  const messageIdMatch = responseText.match(/<MessageId>(.*?)<\/MessageId>/);
  const messageId = messageIdMatch ? messageIdMatch[1] : `ses_${Date.now()}`;
  
  return {
    success: true,
    messageId,
    to: validated.to,
    subject: validated.subject,
    provider: 'aws-ses',
    region: env.AWS_REGION,
    timestamp: new Date().toISOString()
  };
}

// Send bulk email using AWS SES templates
async function sendBulkEmail(args: unknown, env: Env): Promise<unknown> {
  const validated = sendBulkEmailSchema.parse(args);
  const fromEmail = env.EMAIL_DEFAULT_FROM || 'noreply@example.com';
  
  const results = [];
  
  // AWS SES doesn't have native bulk send with templates like SendGrid
  // We'll send individual templated emails
  for (const recipient of validated.recipients) {
    try {
      const params = new URLSearchParams({
        'Action': 'SendTemplatedEmail',
        'Source': fromEmail,
        'Template': validated.templateName,
        'TemplateData': JSON.stringify({
          ...validated.globalData,
          ...recipient.data
        }),
        'Version': '2010-12-01'
      });
      
      params.append('Destination.ToAddresses.member.1', recipient.email);
      
      const url = `https://ses.${env.AWS_REGION}.amazonaws.com`;
      const body = params.toString();
      
      const headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Host': `ses.${env.AWS_REGION}.amazonaws.com`
      };
      
      const signedHeaders = await signAwsRequest('POST', url, headers, body, env);
      
      const response = await fetch(url, {
        method: 'POST',
        headers: signedHeaders,
        body
      });
      
      if (response.ok) {
        const responseText = await response.text();
        const messageIdMatch = responseText.match(/<MessageId>(.*?)<\/MessageId>/);
        results.push({
          email: recipient.email,
          success: true,
          messageId: messageIdMatch ? messageIdMatch[1] : `ses_${Date.now()}`
        });
      } else {
        results.push({
          email: recipient.email,
          success: false,
          error: await response.text()
        });
      }
    } catch (error) {
      results.push({
        email: recipient.email,
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  }
  
  return {
    success: true,
    results,
    templateName: validated.templateName,
    totalRecipients: validated.recipients.length,
    provider: 'aws-ses',
    region: env.AWS_REGION,
    timestamp: new Date().toISOString()
  };
}

// Get available templates
async function getTemplates(env: Env): Promise<unknown> {
  const params = new URLSearchParams({
    'Action': 'ListTemplates',
    'MaxItems': '50',
    'Version': '2010-12-01'
  });
  
  const url = `https://ses.${env.AWS_REGION}.amazonaws.com`;
  const body = params.toString();
  
  const headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    'Host': `ses.${env.AWS_REGION}.amazonaws.com`
  };
  
  const signedHeaders = await signAwsRequest('POST', url, headers, body, env);
  
  const response = await fetch(url, {
    method: 'POST',
    headers: signedHeaders,
    body
  });
  
  if (!response.ok) {
    const error = await response.text();
    throw new Error(`AWS SES templates error: ${error}`);
  }
  
  const responseText = await response.text();
  const templateMatches = responseText.matchAll(/<Name>(.*?)<\/Name>/g);
  const templates = Array.from(templateMatches).map(match => ({
    name: match[1],
    provider: 'aws-ses'
  }));
  
  return { templates };
}

// Get email delivery status
async function getEmailStatus(args: unknown, env: Env): Promise<unknown> {
  const validated = getEmailStatusSchema.parse(args);
  
  // AWS SES doesn't provide direct message status lookup
  // This would require SNS topic configuration for delivery notifications
  return {
    messageId: validated.messageId,
    status: 'sent',
    provider: 'aws-ses',
    region: env.AWS_REGION,
    timestamp: new Date().toISOString(),
    note: 'Real-time status requires SNS topic configuration for delivery notifications'
  };
}

// Helper function for error responses
function createErrorResponse(id: string | number | null, code: number, message: string): Response {
  return new Response(JSON.stringify({
    jsonrpc: '2.0',
    error: { code, message },
    id
  }), {
    status: code === -32700 ? 400 : 200,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*'
    }
  });
}