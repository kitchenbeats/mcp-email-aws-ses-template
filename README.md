# MCP AWS SES Email Server

A Model Context Protocol (MCP) server for sending emails via AWS Simple Email Service (SES).

## Features

- 🚀 **Full MCP Protocol Compliance** - JSON-RPC 2.0 with proper error handling
- 📧 **AWS SES Integration** - Send transactional emails via AWS SES
- 🔧 **Multiple Tools** - Single emails, bulk emails, template support
- ⚡ **Cloudflare Workers** - Fast, global edge deployment
- 🔒 **Type Safe** - Full TypeScript with Zod validation
- 💰 **Cost Effective** - AWS SES offers competitive pricing

## Available Tools

### `send_email`
Send a single email to one or more recipients.

**Parameters:**
- `to`: Array of recipient email addresses
- `subject`: Email subject line
- `body`: Email body (HTML or plain text)
- `from`: Sender email (optional, uses default)
- `replyTo`: Reply-to address (optional)

### `send_bulk_email`
Send personalized emails to multiple recipients.

**Parameters:**
- `recipients`: Array of `{email, data}` objects
- `templateName`: AWS SES template name
- `globalData`: Data available to all recipients

### `get_templates`
List available AWS SES templates.

### `get_email_status`
Check delivery status of sent emails (requires SES event publishing).

## Setup

### 1. Set up GitHub Actions (Optional)

To enable automatic deployment, move the deploy.yml file to .github/workflows/deploy.yml:

\`\`\`bash
mkdir -p .github/workflows
mv deploy.yml .github/workflows/deploy.yml
\`\`\`

Or deploy manually using the Cloudflare Workers button:

[![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/GITHUB_USERNAME/mcp-email-aws-ses-template)

### 2. Configure Environment Variables

Set these in your Cloudflare Workers dashboard or via GitHub secrets:

- `AWS_ACCESS_KEY_ID`: Your AWS access key ID
- `AWS_SECRET_ACCESS_KEY`: Your AWS secret access key
- `AWS_REGION`: AWS region (default: us-east-1)
- `EMAIL_DEFAULT_FROM`: Default sender email address (must be verified in SES)

### 3. AWS SES Setup

1. **Verify your sending domain/email** in AWS SES console
2. **Request production access** if sending to non-verified emails
3. **Configure bounce/complaint handling** (recommended)
4. **Set up SNS topics** for delivery notifications (optional)

### 4. Connect to Claude Desktop

Add to your Claude Desktop configuration:

```json
{
  "mcpServers": {
    "email": {
      "url": "https://your-worker.workers.dev",
      "transport": "http"
    }
  }
}
```

## Usage Examples

### Send a Simple Email
```
Please send an email to john@example.com with subject "Meeting Tomorrow" and body "Don't forget our 2pm meeting"
```

### Send Marketing Email with Template
```
Send our weekly newsletter template to all subscribers in the marketing list
```

### Bulk Personalized Emails
```
Send welcome emails to these new users: [list] using the welcome template
```

## Local Development

1. Clone this repository
2. Install dependencies: `npm install`
3. Copy `wrangler.toml.example` to `wrangler.toml`
4. Set your AWS credentials in wrangler.toml
5. Run locally: `npm run dev`
6. Deploy: `npm run deploy`

## Error Handling

The server provides detailed error messages for:
- Invalid email addresses
- Missing AWS credentials
- SES API failures
- Rate limiting
- Unverified sender addresses
- Template not found

## AWS SES Considerations

- **Sandbox Mode**: New AWS accounts start in sandbox mode (can only send to verified emails)
- **Sending Limits**: AWS SES has sending quotas that increase over time
- **Bounce Handling**: Configure SNS topics to handle bounces and complaints
- **Reputation**: Monitor your sending reputation in the SES console

## Support

For issues or questions:
- Check the [MCP Creator documentation](https://mcp-creator.com/docs)
- Open an issue in this repository
- Contact support via the MCP Creator platform
- Review [AWS SES documentation](https://docs.aws.amazon.com/ses/)
