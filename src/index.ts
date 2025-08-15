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
  },
  {
    name: 'get_sending_quota',
    description: 'Get your AWS SES sending limits and usage',
    inputSchema: {
      type: 'object',
      properties: {}
    }
  },
  {
    name: 'get_send_statistics',
    description: 'Get sending statistics for the last 2 weeks',
    inputSchema: {
      type: 'object',
      properties: {}
    }
  },
  {
    name: 'verify_email_identity',
    description: 'Verify a new email address for sending',
    inputSchema: {
      type: 'object',
      properties: {
        email: {
          type: 'string',
          description: 'Email address to verify'
        }
      },
      required: ['email']
    }
  },
  {
    name: 'list_verified_identities',
    description: 'List all verified email addresses and domains',
    inputSchema: {
      type: 'object',
      properties: {}
    }
  },
  {
    name: 'delete_identity',
    description: 'Remove a verified email or domain',
    inputSchema: {
      type: 'object',
      properties: {
        identity: {
          type: 'string',
          description: 'Email address or domain to remove'
        }
      },
      required: ['identity']
    }
  },
  {
    name: 'get_suppression_list',
    description: 'Get emails in the suppression list (bounces, complaints)',
    inputSchema: {
      type: 'object',
      properties: {
        reason: {
          type: 'string',
          enum: ['BOUNCE', 'COMPLAINT'],
          description: 'Type of suppression to retrieve'
        }
      }
    }
  },
  {
    name: 'create_template',
    description: 'Create a new AWS SES email template',
    inputSchema: {
      type: 'object',
      properties: {
        templateName: {
          type: 'string',
          description: 'Unique name for the template'
        },
        subject: {
          type: 'string',
          description: 'Subject line template (can include {{variables}})'
        },
        htmlBody: {
          type: 'string',
          description: 'HTML version of the email body (can include {{variables}})'
        },
        textBody: {
          type: 'string',
          description: 'Text version of the email body (can include {{variables}})'
        }
      },
      required: ['templateName', 'subject']
    }
  },
  {
    name: 'update_template',
    description: 'Update an existing AWS SES email template',
    inputSchema: {
      type: 'object',
      properties: {
        templateName: {
          type: 'string',
          description: 'Name of the template to update'
        },
        subject: {
          type: 'string',
          description: 'Subject line template (can include {{variables}})'
        },
        htmlBody: {
          type: 'string',
          description: 'HTML version of the email body (can include {{variables}})'
        },
        textBody: {
          type: 'string',
          description: 'Text version of the email body (can include {{variables}})'
        }
      },
      required: ['templateName']
    }
  },
  {
    name: 'delete_template',
    description: 'Delete an AWS SES email template',
    inputSchema: {
      type: 'object',
      properties: {
        templateName: {
          type: 'string',
          description: 'Name of the template to delete'
        }
      },
      required: ['templateName']
    }
  },
  {
    name: 'get_template',
    description: 'Get details of a specific AWS SES email template',
    inputSchema: {
      type: 'object',
      properties: {
        templateName: {
          type: 'string',
          description: 'Name of the template to retrieve'
        }
      },
      required: ['templateName']
    }
  },
  {
    name: 'add_to_suppression_list',
    description: 'Add email addresses to the suppression list',
    inputSchema: {
      type: 'object',
      properties: {
        emails: {
          type: 'array',
          items: { type: 'string' },
          description: 'Email addresses to suppress'
        },
        reason: {
          type: 'string',
          enum: ['BOUNCE', 'COMPLAINT'],
          description: 'Reason for suppression'
        }
      },
      required: ['emails', 'reason']
    }
  },
  {
    name: 'remove_from_suppression_list',
    description: 'Remove email addresses from the suppression list',
    inputSchema: {
      type: 'object',
      properties: {
        emails: {
          type: 'array',
          items: { type: 'string' },
          description: 'Email addresses to remove from suppression'
        }
      },
      required: ['emails']
    }
  },
  {
    name: 'get_account_send_enabled',
    description: 'Check if sending is enabled for the AWS SES account',
    inputSchema: {
      type: 'object',
      properties: {}
    }
  },
  {
    name: 'put_account_send_enabled',
    description: 'Enable or disable sending for the AWS SES account',
    inputSchema: {
      type: 'object',
      properties: {
        enabled: {
          type: 'boolean',
          description: 'Whether to enable or disable sending'
        }
      },
      required: ['enabled']
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
      
      case 'get_sending_quota':
        result = await getSendingQuota(env);
        break;
      
      case 'get_send_statistics':
        result = await getSendStatistics(env);
        break;
      
      case 'verify_email_identity':
        result = await verifyEmailIdentity(params.arguments, env);
        break;
      
      case 'list_verified_identities':
        result = await listVerifiedIdentities(env);
        break;
      
      case 'delete_identity':
        result = await deleteIdentity(params.arguments, env);
        break;
      
      case 'get_suppression_list':
        result = await getSuppressionList(params.arguments, env);
        break;
      
      case 'create_template':
        result = await createTemplate(params.arguments, env);
        break;
      
      case 'update_template':
        result = await updateTemplate(params.arguments, env);
        break;
      
      case 'delete_template':
        result = await deleteTemplate(params.arguments, env);
        break;
      
      case 'get_template':
        result = await getTemplate(params.arguments, env);
        break;
      
      case 'add_to_suppression_list':
        result = await addToSuppressionList(params.arguments, env);
        break;
      
      case 'remove_from_suppression_list':
        result = await removeFromSuppressionList(params.arguments, env);
        break;
      
      case 'get_account_send_enabled':
        result = await getAccountSendEnabled(env);
        break;
      
      case 'put_account_send_enabled':
        result = await putAccountSendEnabled(params.arguments, env);
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
    new URL(url).pathname || '/',
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
  const kDate = await hmacSha256Raw(encoder.encode(`AWS4${key}`).buffer, date);
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

// Send single email via AWS SES V2 API
async function sendEmail(args: unknown, env: Env): Promise<unknown> {
  const validated = sendEmailSchema.parse(args);
  const fromEmail = validated.from || env.EMAIL_DEFAULT_FROM || 'noreply@example.com';
  
  // V2 API endpoint
  const url = `https://email.${env.AWS_REGION}.amazonaws.com/v2/email/outbound-emails`;
  
  // V2 API uses JSON instead of URL-encoded
  const body = JSON.stringify({
    FromEmailAddress: fromEmail,
    Destination: {
      ToAddresses: validated.to
    },
    Content: {
      Simple: {
        Subject: {
          Data: validated.subject,
          Charset: 'UTF-8'
        },
        Body: validated.isHtml ? {
          Html: {
            Data: validated.body,
            Charset: 'UTF-8'
          }
        } : {
          Text: {
            Data: validated.body,
            Charset: 'UTF-8'
          }
        }
      }
    },
    ...(validated.replyTo && { ReplyToAddresses: [validated.replyTo] })
  });
  
  const headers = {
    'Content-Type': 'application/json',
    'Host': `email.${env.AWS_REGION}.amazonaws.com`
  };
  
  const signedHeaders = await signAwsRequest('POST', url, headers, body, env);
  
  const response = await fetch(url, {
    method: 'POST',
    headers: signedHeaders,
    body
  });
  
  if (!response.ok) {
    const error = await response.text();
    throw new Error(`AWS SES V2 API error (${response.status}): ${error}`);
  }
  
  // V2 API returns JSON
  const result: any = await response.json();
  
  return {
    success: true,
    messageId: result.MessageId || `ses_${Date.now()}`,
    to: validated.to,
    subject: validated.subject,
    provider: 'aws-ses-v2',
    region: env.AWS_REGION,
    timestamp: new Date().toISOString()
  };
}

// Send bulk email using AWS SES V2 templates
async function sendBulkEmail(args: unknown, env: Env): Promise<unknown> {
  const validated = sendBulkEmailSchema.parse(args);
  const fromEmail = env.EMAIL_DEFAULT_FROM || 'noreply@example.com';
  
  const results = [];
  
  // V2 API - send bulk templated emails
  for (const recipient of validated.recipients) {
    try {
      const url = `https://email.${env.AWS_REGION}.amazonaws.com/v2/email/outbound-emails`;
      
      // V2 API uses JSON
      const body = JSON.stringify({
        FromEmailAddress: fromEmail,
        Destination: {
          ToAddresses: [recipient.email]
        },
        Content: {
          Template: {
            TemplateName: validated.templateName,
            TemplateData: JSON.stringify({
              ...validated.globalData,
              ...recipient.data
            })
          }
        }
      });
      
      const headers = {
        'Content-Type': 'application/json',
        'Host': `email.${env.AWS_REGION}.amazonaws.com`
      };
      
      const signedHeaders = await signAwsRequest('POST', url, headers, body, env);
      
      const response = await fetch(url, {
        method: 'POST',
        headers: signedHeaders,
        body
      });
      
      if (response.ok) {
        const result: any = await response.json();
        results.push({
          email: recipient.email,
          success: true,
          messageId: result.MessageId || `ses_${Date.now()}`
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
    provider: 'aws-ses-v2',
    region: env.AWS_REGION,
    timestamp: new Date().toISOString()
  };
}

// Get available templates using V2 API
async function getTemplates(env: Env): Promise<unknown> {
  // V2 API endpoint for listing email templates
  const url = `https://email.${env.AWS_REGION}.amazonaws.com/v2/email/templates`;
  
  const headers = {
    'Content-Type': 'application/json',
    'Host': `email.${env.AWS_REGION}.amazonaws.com`
  };
  
  const signedHeaders = await signAwsRequest('GET', url, headers, '', env);
  
  const response = await fetch(url, {
    method: 'GET',
    headers: signedHeaders
  });
  
  if (!response.ok) {
    const error = await response.text();
    throw new Error(`AWS SES V2 templates error (${response.status}): ${error}`);
  }
  
  // V2 API returns JSON
  const result: any = await response.json();
  
  const templates = (result.TemplatesMetadata || []).map((template: any) => ({
    name: template.TemplateName,
    createdAt: template.CreatedTimestamp,
    provider: 'aws-ses-v2'
  }));
  
  return { 
    templates,
    count: templates.length,
    provider: 'aws-ses-v2',
    region: env.AWS_REGION,
    timestamp: new Date().toISOString()
  };
}

// Get email delivery status using V2 API
async function getEmailStatus(args: unknown, env: Env): Promise<unknown> {
  const validated = getEmailStatusSchema.parse(args);
  
  // AWS SES V2 doesn't provide direct message status lookup by message ID alone
  // For production use, you would need to:
  // 1. Configure SNS topics for bounce/complaint notifications
  // 2. Use CloudWatch Events for delivery tracking
  // 3. Store message tracking data in your own database
  
  // However, we can check account-level sending statistics
  try {
    // Get recent sending statistics to provide context
    const statsUrl = `https://email.${env.AWS_REGION}.amazonaws.com/v2/email/account`;
    
    const headers = {
      'Content-Type': 'application/json',
      'Host': `email.${env.AWS_REGION}.amazonaws.com`
    };
    
    const signedHeaders = await signAwsRequest('GET', statsUrl, headers, '', env);
    
    const response = await fetch(statsUrl, {
      method: 'GET',
      headers: signedHeaders
    });
    
    let accountStats: any = {};
    if (response.ok) {
      accountStats = await response.json();
    }
    
    return {
      messageId: validated.messageId,
      status: 'unknown',
      provider: 'aws-ses-v2',
      region: env.AWS_REGION,
      timestamp: new Date().toISOString(),
      accountStats: {
        sendingEnabled: (accountStats as any)?.SendingEnabled || false,
        enforcementStatus: (accountStats as any)?.EnforcementStatus || 'unknown'
      },
      recommendations: [
        'Configure SNS topics for bounce and complaint notifications',
        'Use CloudWatch Events for delivery status tracking',
        'Implement your own message tracking database',
        'Consider using SES Configuration Sets for detailed tracking'
      ],
      note: 'AWS SES V2 API does not provide direct message status lookup. Message was submitted to SES but delivery status requires additional configuration.'
    };
  } catch (error) {
    return {
      messageId: validated.messageId,
      status: 'unknown',
      provider: 'aws-ses-v2',
      region: env.AWS_REGION,
      timestamp: new Date().toISOString(),
      error: error instanceof Error ? error.message : 'Unknown error',
      note: 'Unable to retrieve message status. AWS SES V2 API does not provide direct message status lookup.'
    };
  }
}

// Get sending quota using V2 API
async function getSendingQuota(env: Env): Promise<unknown> {
  // V2 API endpoint for account details
  const url = `https://email.${env.AWS_REGION}.amazonaws.com/v2/email/account`;
  
  const headers = {
    'Content-Type': 'application/json',
    'Host': `email.${env.AWS_REGION}.amazonaws.com`
  };
  
  const signedHeaders = await signAwsRequest('GET', url, headers, '', env);
  
  const response = await fetch(url, {
    method: 'GET',
    headers: signedHeaders
  });
  
  if (!response.ok) {
    const error = await response.text();
    throw new Error(`AWS SES V2 quota error (${response.status}): ${error}`);
  }
  
  // V2 API returns JSON
  const result: any = await response.json();
  
  return {
    max24HourSend: result.SendQuota?.Max24HourSend || 0,
    maxSendRate: result.SendQuota?.MaxSendRate || 0,
    sentLast24Hours: result.SendQuota?.SentLast24Hours || 0,
    remainingToday: (result.SendQuota?.Max24HourSend || 0) - (result.SendQuota?.SentLast24Hours || 0),
    percentageUsed: result.SendQuota?.Max24HourSend ? 
      ((result.SendQuota?.SentLast24Hours || 0) / result.SendQuota.Max24HourSend) * 100 : 0,
    provider: 'aws-ses-v2',
    region: env.AWS_REGION,
    timestamp: new Date().toISOString()
  };
}

// Get send statistics using V2 API
async function getSendStatistics(env: Env): Promise<unknown> {
  // V2 API doesn't have a direct equivalent - return account metrics instead
  const url = `https://email.${env.AWS_REGION}.amazonaws.com/v2/email/account`;
  
  const headers = {
    'Content-Type': 'application/json',
    'Host': `email.${env.AWS_REGION}.amazonaws.com`
  };
  
  const signedHeaders = await signAwsRequest('GET', url, headers, '', env);
  
  const response = await fetch(url, {
    method: 'GET',
    headers: signedHeaders
  });
  
  if (!response.ok) {
    const error = await response.text();
    throw new Error(`AWS SES V2 statistics error (${response.status}): ${error}`);
  }
  
  // V2 API returns JSON with different structure
  const result: any = await response.json();
  
  // Return simplified statistics from account data
  return {
    dataPoints: [], // V2 API doesn't provide historical data in the same way
    sendingEnabled: result.ProductionAccessEnabled || false,
    sendQuota: result.SendQuota || {},
    suppressionAttributes: result.SuppressionAttributes || {},
    provider: 'aws-ses-v2',
    region: env.AWS_REGION,
    timestamp: new Date().toISOString(),
    note: 'V2 API provides account-level metrics. For detailed statistics, use CloudWatch.'
  };
}

// Verify email identity using V2 API
async function verifyEmailIdentity(args: unknown, env: Env): Promise<unknown> {
  const validated = z.object({
    email: z.string().email()
  }).parse(args);
  
  // V2 API endpoint for creating email identity
  const url = `https://email.${env.AWS_REGION}.amazonaws.com/v2/email/identities`;
  
  // V2 API uses JSON
  const body = JSON.stringify({
    EmailIdentity: validated.email
  });
  
  const headers = {
    'Content-Type': 'application/json',
    'Host': `email.${env.AWS_REGION}.amazonaws.com`
  };
  
  const signedHeaders = await signAwsRequest('POST', url, headers, body, env);
  
  const response = await fetch(url, {
    method: 'POST',
    headers: signedHeaders,
    body
  });
  
  if (!response.ok) {
    const error = await response.text();
    // If identity already exists, that's okay
    if (response.status === 409) {
      return {
        success: true,
        email: validated.email,
        status: 'already_verified',
        message: `Email ${validated.email} is already in the verification process or verified.`,
        provider: 'aws-ses-v2',
        region: env.AWS_REGION,
        timestamp: new Date().toISOString()
      };
    }
    throw new Error(`AWS SES V2 verify error (${response.status}): ${error}`);
  }
  
  // V2 API returns JSON
  const result: any = await response.json();
  
  return {
    success: true,
    email: validated.email,
    status: result.VerifiedForSendingStatus ? 'verified' : 'verification_sent',
    identityType: result.IdentityType || 'EMAIL_ADDRESS',
    message: `Verification email sent to ${validated.email}. Please check inbox and click the verification link.`,
    provider: 'aws-ses-v2',
    region: env.AWS_REGION,
    timestamp: new Date().toISOString()
  };
}

// List verified identities using V2 API
async function listVerifiedIdentities(env: Env): Promise<unknown> {
  // V2 API endpoint for listing email identities
  const url = `https://email.${env.AWS_REGION}.amazonaws.com/v2/email/identities`;
  
  const headers = {
    'Content-Type': 'application/json',
    'Host': `email.${env.AWS_REGION}.amazonaws.com`
  };
  
  const signedHeaders = await signAwsRequest('GET', url, headers, '', env);
  
  const response = await fetch(url, {
    method: 'GET',
    headers: signedHeaders
  });
  
  if (!response.ok) {
    const error = await response.text();
    throw new Error(`AWS SES V2 list identities error (${response.status}): ${error}`);
  }
  
  // V2 API returns JSON
  const result: any = await response.json();
  
  // Separate emails and domains
  const emails: string[] = [];
  const domains: string[] = [];
  
  if (result.EmailIdentities) {
    for (const identity of result.EmailIdentities) {
      const identityName = identity.IdentityName || '';
      if (identityName.includes('@')) {
        emails.push(identityName);
      } else if (identityName) {
        domains.push(identityName);
      }
    }
  }
  
  return {
    emails,
    domains,
    totalCount: emails.length + domains.length,
    identities: result.EmailIdentities || [],
    nextToken: result.NextToken,
    provider: 'aws-ses-v2',
    region: env.AWS_REGION,
    timestamp: new Date().toISOString()
  };
}

// Delete identity using V2 API
async function deleteIdentity(args: unknown, env: Env): Promise<unknown> {
  const validated = z.object({
    identity: z.string()
  }).parse(args);
  
  // V2 API endpoint for deleting email identity
  const url = `https://email.${env.AWS_REGION}.amazonaws.com/v2/email/identities/${encodeURIComponent(validated.identity)}`;
  
  const headers = {
    'Content-Type': 'application/json',
    'Host': `email.${env.AWS_REGION}.amazonaws.com`
  };
  
  const signedHeaders = await signAwsRequest('DELETE', url, headers, '', env);
  
  const response = await fetch(url, {
    method: 'DELETE',
    headers: signedHeaders
  });
  
  if (!response.ok) {
    const error = await response.text();
    // 404 means identity doesn't exist, which is fine
    if (response.status === 404) {
      return {
        success: true,
        identity: validated.identity,
        message: `Identity ${validated.identity} not found or already deleted`,
        provider: 'aws-ses-v2',
        region: env.AWS_REGION,
        timestamp: new Date().toISOString()
      };
    }
    throw new Error(`AWS SES V2 delete identity error (${response.status}): ${error}`);
  }
  
  return {
    success: true,
    identity: validated.identity,
    message: `Successfully removed ${validated.identity} from verified identities`,
    provider: 'aws-ses-v2',
    region: env.AWS_REGION,
    timestamp: new Date().toISOString()
  };
}

// Get suppression list using V2 API
async function getSuppressionList(args: unknown, env: Env): Promise<unknown> {
  const validated = z.object({
    reason: z.enum(['BOUNCE', 'COMPLAINT']).optional()
  }).parse(args || {});
  
  // V2 API endpoint for suppression list
  let url = `https://email.${env.AWS_REGION}.amazonaws.com/v2/email/suppression/addresses`;
  
  // Add query parameters if reason specified
  if (validated.reason) {
    url += `?Reason=${validated.reason}`;
  }
  
  const headers = {
    'Content-Type': 'application/json',
    'Host': `email.${env.AWS_REGION}.amazonaws.com`
  };
  
  const signedHeaders = await signAwsRequest('GET', url, headers, '', env);
  
  const response = await fetch(url, {
    method: 'GET',
    headers: signedHeaders
  });
  
  if (!response.ok) {
    const error = await response.text();
    throw new Error(`AWS SES V2 suppression list error (${response.status}): ${error}`);
  }
  
  // V2 API returns JSON
  const result: any = await response.json();
  
  const suppressedEmails = (result.SuppressedDestinationSummaries || []).map((item: any) => ({
    email: item.EmailAddress,
    reason: item.Reason,
    lastUpdateTime: item.LastUpdateTime
  }));
  
  return {
    suppressedEmails: suppressedEmails.map((item: any) => item.email),
    suppressedDetails: suppressedEmails,
    reason: validated.reason || 'ALL',
    count: suppressedEmails.length,
    nextToken: result.NextToken,
    provider: 'aws-ses-v2',
    region: env.AWS_REGION,
    timestamp: new Date().toISOString()
  };
}

// Create email template using V2 API
async function createTemplate(args: unknown, env: Env): Promise<unknown> {
  const validated = z.object({
    templateName: z.string(),
    subject: z.string(),
    htmlBody: z.string().optional(),
    textBody: z.string().optional()
  }).parse(args);

  // V2 API endpoint for creating email template
  const url = `https://email.${env.AWS_REGION}.amazonaws.com/v2/email/templates`;
  
  // V2 API uses JSON
  const body = JSON.stringify({
    TemplateName: validated.templateName,
    TemplateContent: {
      Subject: validated.subject,
      Html: validated.htmlBody || undefined,
      Text: validated.textBody || undefined
    }
  });
  
  const headers = {
    'Content-Type': 'application/json',
    'Host': `email.${env.AWS_REGION}.amazonaws.com`
  };
  
  const signedHeaders = await signAwsRequest('POST', url, headers, body, env);
  
  const response = await fetch(url, {
    method: 'POST',
    headers: signedHeaders,
    body
  });
  
  if (!response.ok) {
    const error = await response.text();
    // Handle conflict if template already exists
    if (response.status === 409) {
      throw new Error(`Template '${validated.templateName}' already exists`);
    }
    throw new Error(`AWS SES V2 create template error (${response.status}): ${error}`);
  }
  
  return {
    success: true,
    templateName: validated.templateName,
    message: `Template '${validated.templateName}' created successfully`,
    provider: 'aws-ses-v2',
    region: env.AWS_REGION,
    timestamp: new Date().toISOString()
  };
}

// Update email template using V2 API
async function updateTemplate(args: unknown, env: Env): Promise<unknown> {
  const validated = z.object({
    templateName: z.string(),
    subject: z.string().optional(),
    htmlBody: z.string().optional(),
    textBody: z.string().optional()
  }).parse(args);

  // V2 API endpoint for updating email template
  const url = `https://email.${env.AWS_REGION}.amazonaws.com/v2/email/templates/${encodeURIComponent(validated.templateName)}`;
  
  // V2 API uses JSON
  const body = JSON.stringify({
    TemplateContent: {
      Subject: validated.subject || undefined,
      Html: validated.htmlBody || undefined,
      Text: validated.textBody || undefined
    }
  });
  
  const headers = {
    'Content-Type': 'application/json',
    'Host': `email.${env.AWS_REGION}.amazonaws.com`
  };
  
  const signedHeaders = await signAwsRequest('PUT', url, headers, body, env);
  
  const response = await fetch(url, {
    method: 'PUT',
    headers: signedHeaders,
    body
  });
  
  if (!response.ok) {
    const error = await response.text();
    // Handle not found
    if (response.status === 404) {
      throw new Error(`Template '${validated.templateName}' not found`);
    }
    throw new Error(`AWS SES V2 update template error (${response.status}): ${error}`);
  }
  
  return {
    success: true,
    templateName: validated.templateName,
    message: `Template '${validated.templateName}' updated successfully`,
    provider: 'aws-ses-v2',
    region: env.AWS_REGION,
    timestamp: new Date().toISOString()
  };
}

// Delete email template using V2 API
async function deleteTemplate(args: unknown, env: Env): Promise<unknown> {
  const validated = z.object({
    templateName: z.string()
  }).parse(args);

  // V2 API endpoint for deleting email template
  const url = `https://email.${env.AWS_REGION}.amazonaws.com/v2/email/templates/${encodeURIComponent(validated.templateName)}`;
  
  const headers = {
    'Content-Type': 'application/json',
    'Host': `email.${env.AWS_REGION}.amazonaws.com`
  };
  
  const signedHeaders = await signAwsRequest('DELETE', url, headers, '', env);
  
  const response = await fetch(url, {
    method: 'DELETE',
    headers: signedHeaders
  });
  
  if (!response.ok) {
    const error = await response.text();
    // Handle not found
    if (response.status === 404) {
      return {
        success: true,
        templateName: validated.templateName,
        message: `Template '${validated.templateName}' not found or already deleted`,
        provider: 'aws-ses-v2',
        region: env.AWS_REGION,
        timestamp: new Date().toISOString()
      };
    }
    throw new Error(`AWS SES V2 delete template error (${response.status}): ${error}`);
  }
  
  return {
    success: true,
    templateName: validated.templateName,
    message: `Template '${validated.templateName}' deleted successfully`,
    provider: 'aws-ses-v2',
    region: env.AWS_REGION,
    timestamp: new Date().toISOString()
  };
}

// Get email template details using V2 API
async function getTemplate(args: unknown, env: Env): Promise<unknown> {
  const validated = z.object({
    templateName: z.string()
  }).parse(args);

  // V2 API endpoint for getting email template
  const url = `https://email.${env.AWS_REGION}.amazonaws.com/v2/email/templates/${encodeURIComponent(validated.templateName)}`;
  
  const headers = {
    'Content-Type': 'application/json',
    'Host': `email.${env.AWS_REGION}.amazonaws.com`
  };
  
  const signedHeaders = await signAwsRequest('GET', url, headers, '', env);
  
  const response = await fetch(url, {
    method: 'GET',
    headers: signedHeaders
  });
  
  if (!response.ok) {
    const error = await response.text();
    // Handle not found
    if (response.status === 404) {
      throw new Error(`Template '${validated.templateName}' not found`);
    }
    throw new Error(`AWS SES V2 get template error (${response.status}): ${error}`);
  }
  
  // V2 API returns JSON
  const result: any = await response.json();
  
  return {
    templateName: result.TemplateName,
    subject: result.TemplateContent?.Subject,
    htmlBody: result.TemplateContent?.Html,
    textBody: result.TemplateContent?.Text,
    createdTimestamp: result.CreatedTimestamp,
    provider: 'aws-ses-v2',
    region: env.AWS_REGION,
    timestamp: new Date().toISOString()
  };
}

// Add emails to suppression list using V2 API
async function addToSuppressionList(args: unknown, env: Env): Promise<unknown> {
  const validated = z.object({
    emails: z.array(z.string().email()),
    reason: z.enum(['BOUNCE', 'COMPLAINT'])
  }).parse(args);

  const results = [];
  
  // V2 API requires individual requests for each email
  for (const email of validated.emails) {
    try {
      // V2 API endpoint for adding to suppression list
      const url = `https://email.${env.AWS_REGION}.amazonaws.com/v2/email/suppression/addresses`;
      
      // V2 API uses JSON
      const body = JSON.stringify({
        EmailAddress: email,
        Reason: validated.reason
      });
      
      const headers = {
        'Content-Type': 'application/json',
        'Host': `email.${env.AWS_REGION}.amazonaws.com`
      };
      
      const signedHeaders = await signAwsRequest('PUT', url, headers, body, env);
      
      const response = await fetch(url, {
        method: 'PUT',
        headers: signedHeaders,
        body
      });
      
      if (response.ok) {
        results.push({
          email,
          success: true,
          reason: validated.reason
        });
      } else {
        const error = await response.text();
        results.push({
          email,
          success: false,
          error: `Error (${response.status}): ${error}`
        });
      }
    } catch (error) {
      results.push({
        email,
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  }
  
  return {
    success: true,
    results,
    reason: validated.reason,
    totalEmails: validated.emails.length,
    successCount: results.filter(r => r.success).length,
    provider: 'aws-ses-v2',
    region: env.AWS_REGION,
    timestamp: new Date().toISOString()
  };
}

// Remove emails from suppression list using V2 API
async function removeFromSuppressionList(args: unknown, env: Env): Promise<unknown> {
  const validated = z.object({
    emails: z.array(z.string().email())
  }).parse(args);

  const results = [];
  
  // V2 API requires individual requests for each email
  for (const email of validated.emails) {
    try {
      // V2 API endpoint for removing from suppression list
      const url = `https://email.${env.AWS_REGION}.amazonaws.com/v2/email/suppression/addresses/${encodeURIComponent(email)}`;
      
      const headers = {
        'Content-Type': 'application/json',
        'Host': `email.${env.AWS_REGION}.amazonaws.com`
      };
      
      const signedHeaders = await signAwsRequest('DELETE', url, headers, '', env);
      
      const response = await fetch(url, {
        method: 'DELETE',
        headers: signedHeaders
      });
      
      if (response.ok || response.status === 404) {
        // 404 means email wasn't in suppression list, which is fine
        results.push({
          email,
          success: true,
          message: response.status === 404 ? 'Email not in suppression list' : 'Removed from suppression list'
        });
      } else {
        const error = await response.text();
        results.push({
          email,
          success: false,
          error: `Error (${response.status}): ${error}`
        });
      }
    } catch (error) {
      results.push({
        email,
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  }
  
  return {
    success: true,
    results,
    totalEmails: validated.emails.length,
    successCount: results.filter(r => r.success).length,
    provider: 'aws-ses-v2',
    region: env.AWS_REGION,
    timestamp: new Date().toISOString()
  };
}

// Get account send enabled status using V2 API
async function getAccountSendEnabled(env: Env): Promise<unknown> {
  // V2 API endpoint for account details
  const url = `https://email.${env.AWS_REGION}.amazonaws.com/v2/email/account`;
  
  const headers = {
    'Content-Type': 'application/json',
    'Host': `email.${env.AWS_REGION}.amazonaws.com`
  };
  
  const signedHeaders = await signAwsRequest('GET', url, headers, '', env);
  
  const response = await fetch(url, {
    method: 'GET',
    headers: signedHeaders
  });
  
  if (!response.ok) {
    const error = await response.text();
    throw new Error(`AWS SES V2 account details error (${response.status}): ${error}`);
  }
  
  // V2 API returns JSON
  const result: any = await response.json();
  
  return {
    sendingEnabled: result.SendingEnabled || false,
    enforcementStatus: result.EnforcementStatus,
    productionAccess: result.ProductionAccessEnabled || false,
    provider: 'aws-ses-v2',
    region: env.AWS_REGION,
    timestamp: new Date().toISOString()
  };
}

// Enable/disable account sending using V2 API
async function putAccountSendEnabled(args: unknown, env: Env): Promise<unknown> {
  const validated = z.object({
    enabled: z.boolean()
  }).parse(args);

  // V2 API endpoint for updating account sending
  const url = `https://email.${env.AWS_REGION}.amazonaws.com/v2/email/account/sending-enabled`;
  
  // V2 API uses JSON
  const body = JSON.stringify({
    Enabled: validated.enabled
  });
  
  const headers = {
    'Content-Type': 'application/json',
    'Host': `email.${env.AWS_REGION}.amazonaws.com`
  };
  
  const signedHeaders = await signAwsRequest('PUT', url, headers, body, env);
  
  const response = await fetch(url, {
    method: 'PUT',
    headers: signedHeaders,
    body
  });
  
  if (!response.ok) {
    const error = await response.text();
    throw new Error(`AWS SES V2 set send enabled error (${response.status}): ${error}`);
  }
  
  return {
    success: true,
    sendingEnabled: validated.enabled,
    message: `Account sending ${validated.enabled ? 'enabled' : 'disabled'} successfully`,
    provider: 'aws-ses-v2',
    region: env.AWS_REGION,
    timestamp: new Date().toISOString()
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