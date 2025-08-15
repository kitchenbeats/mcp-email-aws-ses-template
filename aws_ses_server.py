#!/usr/bin/env python3
"""
FastMCP v2 AWS SES Email Server
Production-ready MCP server for AWS SES email operations with HTTP transport.
"""

import os
import json
from typing import List, Dict, Any, Optional, Union
from datetime import datetime

import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from fastmcp import FastMCP
from pydantic import BaseModel, EmailStr, Field
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize FastMCP server
mcp = FastMCP("AWS SES Email Server", description="Production-ready AWS SES email operations via FastMCP v2")

# Pydantic models for request validation
class EmailRecipient(BaseModel):
    email: EmailStr
    data: Optional[Dict[str, Any]] = {}

class SendEmailRequest(BaseModel):
    to: List[EmailStr]
    subject: str
    body: str
    from_email: Optional[EmailStr] = None
    reply_to: Optional[EmailStr] = None
    is_html: bool = True

class BulkEmailRequest(BaseModel):
    recipients: List[EmailRecipient]
    template_name: str
    global_data: Optional[Dict[str, Any]] = {}

class CreateTemplateRequest(BaseModel):
    template_name: str
    subject: str
    html_body: Optional[str] = None
    text_body: Optional[str] = None

class UpdateTemplateRequest(BaseModel):
    template_name: str
    subject: Optional[str] = None
    html_body: Optional[str] = None
    text_body: Optional[str] = None

class SuppressionRequest(BaseModel):
    emails: List[EmailStr]
    reason: Optional[str] = Field(None, regex="^(BOUNCE|COMPLAINT)$")

# Initialize AWS SES client
def get_ses_client():
    """Get configured AWS SES client"""
    try:
        # Use environment variables or IAM role
        return boto3.client(
            'sesv2',
            region_name=os.getenv('AWS_REGION', 'us-east-1'),
            aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
            aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY')
        )
    except NoCredentialsError:
        raise Exception("AWS credentials not configured. Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables.")

# Email sending tools
@mcp.tool
def send_email(
    to: List[str],
    subject: str,
    body: str,
    from_email: Optional[str] = None,
    reply_to: Optional[str] = None,
    is_html: bool = True
) -> Dict[str, Any]:
    """
    Send an email to one or more recipients via AWS SES.
    
    Args:
        to: List of recipient email addresses
        subject: Email subject line
        body: Email body content (HTML or plain text)
        from_email: Sender email address (must be verified in SES)
        reply_to: Reply-to email address
        is_html: Whether body contains HTML (default: True)
    
    Returns:
        Dict with success status, message ID, and metadata
    """
    try:
        request = SendEmailRequest(
            to=to,
            subject=subject,
            body=body,
            from_email=from_email,
            reply_to=reply_to,
            is_html=is_html
        )
        
        ses_client = get_ses_client()
        
        # Prepare email content
        content = {
            'Simple': {
                'Subject': {'Data': request.subject, 'Charset': 'UTF-8'},
                'Body': {}
            }
        }
        
        if request.is_html:
            content['Simple']['Body']['Html'] = {'Data': request.body, 'Charset': 'UTF-8'}
        else:
            content['Simple']['Body']['Text'] = {'Data': request.body, 'Charset': 'UTF-8'}
        
        # Prepare destination
        destination = {'ToAddresses': request.to}
        
        # Send email
        response = ses_client.send_email(
            FromEmailAddress=request.from_email or os.getenv('EMAIL_DEFAULT_FROM', 'noreply@example.com'),
            Destination=destination,
            Content=content,
            ReplyToAddresses=[request.reply_to] if request.reply_to else None
        )
        
        return {
            'success': True,
            'message_id': response['MessageId'],
            'to': request.to,
            'subject': request.subject,
            'provider': 'aws-ses-v2',
            'region': os.getenv('AWS_REGION', 'us-east-1'),
            'timestamp': datetime.utcnow().isoformat()
        }
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        raise Exception(f"AWS SES Error ({error_code}): {error_message}")
    except Exception as e:
        raise Exception(f"Failed to send email: {str(e)}")

@mcp.tool
def send_bulk_email(
    recipients: List[Dict[str, Any]],
    template_name: str,
    global_data: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Send personalized emails to multiple recipients using AWS SES templates.
    
    Args:
        recipients: List of recipient objects with 'email' and optional 'data' fields
        template_name: AWS SES template name
        global_data: Data available to all recipients
    
    Returns:
        Dict with results for each recipient and summary statistics
    """
    try:
        # Convert recipients to proper format
        recipient_objects = [
            EmailRecipient(email=r['email'], data=r.get('data', {}))
            for r in recipients
        ]
        
        request = BulkEmailRequest(
            recipients=recipient_objects,
            template_name=template_name,
            global_data=global_data or {}
        )
        
        ses_client = get_ses_client()
        results = []
        
        # Send to each recipient individually (SES V2 doesn't have native bulk template sending)
        for recipient in request.recipients:
            try:
                # Merge global and recipient-specific data
                template_data = {**request.global_data, **recipient.data}
                
                response = ses_client.send_email(
                    FromEmailAddress=os.getenv('EMAIL_DEFAULT_FROM', 'noreply@example.com'),
                    Destination={'ToAddresses': [recipient.email]},
                    Content={
                        'Template': {
                            'TemplateName': request.template_name,
                            'TemplateData': json.dumps(template_data)
                        }
                    }
                )
                
                results.append({
                    'email': recipient.email,
                    'success': True,
                    'message_id': response['MessageId']
                })
                
            except ClientError as e:
                results.append({
                    'email': recipient.email,
                    'success': False,
                    'error': f"{e.response['Error']['Code']}: {e.response['Error']['Message']}"
                })
        
        successful = [r for r in results if r['success']]
        
        return {
            'success': True,
            'results': results,
            'template_name': request.template_name,
            'total_recipients': len(request.recipients),
            'successful_sends': len(successful),
            'failed_sends': len(results) - len(successful),
            'provider': 'aws-ses-v2',
            'region': os.getenv('AWS_REGION', 'us-east-1'),
            'timestamp': datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        raise Exception(f"Failed to send bulk email: {str(e)}")

# Template management tools
@mcp.tool
def get_templates() -> Dict[str, Any]:
    """
    List all available AWS SES email templates.
    
    Returns:
        Dict with list of templates and metadata
    """
    try:
        ses_client = get_ses_client()
        
        response = ses_client.list_email_templates()
        
        templates = [
            {
                'name': template['TemplateName'],
                'created_at': template.get('CreatedTimestamp'),
                'provider': 'aws-ses-v2'
            }
            for template in response.get('TemplatesMetadata', [])
        ]
        
        return {
            'templates': templates,
            'count': len(templates),
            'provider': 'aws-ses-v2',
            'region': os.getenv('AWS_REGION', 'us-east-1'),
            'timestamp': datetime.utcnow().isoformat()
        }
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        raise Exception(f"AWS SES Error ({error_code}): {error_message}")

@mcp.tool
def create_template(
    template_name: str,
    subject: str,
    html_body: Optional[str] = None,
    text_body: Optional[str] = None
) -> Dict[str, Any]:
    """
    Create a new AWS SES email template.
    
    Args:
        template_name: Unique name for the template
        subject: Subject line template (can include {{variables}})
        html_body: HTML version of the email body (can include {{variables}})
        text_body: Text version of the email body (can include {{variables}})
    
    Returns:
        Dict with success status and template details
    """
    try:
        request = CreateTemplateRequest(
            template_name=template_name,
            subject=subject,
            html_body=html_body,
            text_body=text_body
        )
        
        ses_client = get_ses_client()
        
        template_content = {
            'Subject': request.subject
        }
        
        if request.html_body:
            template_content['Html'] = request.html_body
        if request.text_body:
            template_content['Text'] = request.text_body
        
        ses_client.create_email_template(
            TemplateName=request.template_name,
            TemplateContent=template_content
        )
        
        return {
            'success': True,
            'template_name': request.template_name,
            'message': f"Template '{request.template_name}' created successfully",
            'provider': 'aws-ses-v2',
            'region': os.getenv('AWS_REGION', 'us-east-1'),
            'timestamp': datetime.utcnow().isoformat()
        }
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        
        if error_code == 'AlreadyExistsException':
            raise Exception(f"Template '{template_name}' already exists")
        
        raise Exception(f"AWS SES Error ({error_code}): {error_message}")

@mcp.tool
def update_template(
    template_name: str,
    subject: Optional[str] = None,
    html_body: Optional[str] = None,
    text_body: Optional[str] = None
) -> Dict[str, Any]:
    """
    Update an existing AWS SES email template.
    
    Args:
        template_name: Name of the template to update
        subject: New subject line template
        html_body: New HTML body content
        text_body: New text body content
    
    Returns:
        Dict with success status and template details
    """
    try:
        request = UpdateTemplateRequest(
            template_name=template_name,
            subject=subject,
            html_body=html_body,
            text_body=text_body
        )
        
        ses_client = get_ses_client()
        
        template_content = {}
        
        if request.subject is not None:
            template_content['Subject'] = request.subject
        if request.html_body is not None:
            template_content['Html'] = request.html_body
        if request.text_body is not None:
            template_content['Text'] = request.text_body
        
        if not template_content:
            raise Exception("At least one field (subject, html_body, text_body) must be provided for update")
        
        ses_client.update_email_template(
            TemplateName=request.template_name,
            TemplateContent=template_content
        )
        
        return {
            'success': True,
            'template_name': request.template_name,
            'message': f"Template '{request.template_name}' updated successfully",
            'provider': 'aws-ses-v2',
            'region': os.getenv('AWS_REGION', 'us-east-1'),
            'timestamp': datetime.utcnow().isoformat()
        }
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        
        if error_code == 'NotFoundException':
            raise Exception(f"Template '{template_name}' not found")
        
        raise Exception(f"AWS SES Error ({error_code}): {error_message}")

@mcp.tool
def delete_template(template_name: str) -> Dict[str, Any]:
    """
    Delete an AWS SES email template.
    
    Args:
        template_name: Name of the template to delete
    
    Returns:
        Dict with success status
    """
    try:
        ses_client = get_ses_client()
        
        ses_client.delete_email_template(TemplateName=template_name)
        
        return {
            'success': True,
            'template_name': template_name,
            'message': f"Template '{template_name}' deleted successfully",
            'provider': 'aws-ses-v2',
            'region': os.getenv('AWS_REGION', 'us-east-1'),
            'timestamp': datetime.utcnow().isoformat()
        }
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        
        if error_code == 'NotFoundException':
            return {
                'success': True,
                'template_name': template_name,
                'message': f"Template '{template_name}' not found or already deleted",
                'provider': 'aws-ses-v2',
                'region': os.getenv('AWS_REGION', 'us-east-1'),
                'timestamp': datetime.utcnow().isoformat()
            }
        
        raise Exception(f"AWS SES Error ({error_code}): {error_message}")

@mcp.tool
def get_template(template_name: str) -> Dict[str, Any]:
    """
    Get details of a specific AWS SES email template.
    
    Args:
        template_name: Name of the template to retrieve
    
    Returns:
        Dict with template details
    """
    try:
        ses_client = get_ses_client()
        
        response = ses_client.get_email_template(TemplateName=template_name)
        
        template = response['TemplateContent']
        
        return {
            'template_name': template_name,
            'subject': template.get('Subject'),
            'html_body': template.get('Html'),
            'text_body': template.get('Text'),
            'created_timestamp': response.get('CreatedTimestamp'),
            'provider': 'aws-ses-v2',
            'region': os.getenv('AWS_REGION', 'us-east-1'),
            'timestamp': datetime.utcnow().isoformat()
        }
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        
        if error_code == 'NotFoundException':
            raise Exception(f"Template '{template_name}' not found")
        
        raise Exception(f"AWS SES Error ({error_code}): {error_message}")

# Identity management tools
@mcp.tool
def verify_email_identity(email: str) -> Dict[str, Any]:
    """
    Verify a new email address for sending.
    
    Args:
        email: Email address to verify
    
    Returns:
        Dict with verification status
    """
    try:
        ses_client = get_ses_client()
        
        response = ses_client.put_email_identity(EmailIdentity=email)
        
        return {
            'success': True,
            'email': email,
            'status': 'verification_sent' if not response.get('VerifiedForSendingStatus') else 'verified',
            'identity_type': response.get('IdentityType', 'EMAIL_ADDRESS'),
            'message': f"Verification email sent to {email}. Please check inbox and click the verification link.",
            'provider': 'aws-ses-v2',
            'region': os.getenv('AWS_REGION', 'us-east-1'),
            'timestamp': datetime.utcnow().isoformat()
        }
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        
        if error_code == 'AlreadyExistsException':
            return {
                'success': True,
                'email': email,
                'status': 'already_verified',
                'message': f"Email {email} is already in the verification process or verified.",
                'provider': 'aws-ses-v2',
                'region': os.getenv('AWS_REGION', 'us-east-1'),
                'timestamp': datetime.utcnow().isoformat()
            }
        
        raise Exception(f"AWS SES Error ({error_code}): {error_message}")

@mcp.tool
def list_verified_identities() -> Dict[str, Any]:
    """
    List all verified email addresses and domains.
    
    Returns:
        Dict with verified identities
    """
    try:
        ses_client = get_ses_client()
        
        response = ses_client.list_email_identities()
        
        emails = []
        domains = []
        
        for identity in response.get('EmailIdentities', []):
            identity_name = identity.get('IdentityName', '')
            if '@' in identity_name:
                emails.append(identity_name)
            elif identity_name:
                domains.append(identity_name)
        
        return {
            'emails': emails,
            'domains': domains,
            'total_count': len(emails) + len(domains),
            'identities': response.get('EmailIdentities', []),
            'next_token': response.get('NextToken'),
            'provider': 'aws-ses-v2',
            'region': os.getenv('AWS_REGION', 'us-east-1'),
            'timestamp': datetime.utcnow().isoformat()
        }
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        raise Exception(f"AWS SES Error ({error_code}): {error_message}")

@mcp.tool
def delete_identity(identity: str) -> Dict[str, Any]:
    """
    Remove a verified email or domain.
    
    Args:
        identity: Email address or domain to remove
    
    Returns:
        Dict with deletion status
    """
    try:
        ses_client = get_ses_client()
        
        ses_client.delete_email_identity(EmailIdentity=identity)
        
        return {
            'success': True,
            'identity': identity,
            'message': f"Successfully removed {identity} from verified identities",
            'provider': 'aws-ses-v2',
            'region': os.getenv('AWS_REGION', 'us-east-1'),
            'timestamp': datetime.utcnow().isoformat()
        }
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        
        if error_code == 'NotFoundException':
            return {
                'success': True,
                'identity': identity,
                'message': f"Identity {identity} not found or already deleted",
                'provider': 'aws-ses-v2',
                'region': os.getenv('AWS_REGION', 'us-east-1'),
                'timestamp': datetime.utcnow().isoformat()
            }
        
        raise Exception(f"AWS SES Error ({error_code}): {error_message}")

# Statistics and monitoring tools
@mcp.tool
def get_sending_quota() -> Dict[str, Any]:
    """
    Get your AWS SES sending limits and usage.
    
    Returns:
        Dict with quota information
    """
    try:
        ses_client = get_ses_client()
        
        response = ses_client.get_account()
        
        send_quota = response.get('SendQuota', {})
        
        max_send = send_quota.get('Max24HourSend', 0)
        sent_last_24h = send_quota.get('SentLast24Hours', 0)
        
        return {
            'max_24_hour_send': max_send,
            'max_send_rate': send_quota.get('MaxSendRate', 0),
            'sent_last_24_hours': sent_last_24h,
            'remaining_today': max_send - sent_last_24h,
            'percentage_used': (sent_last_24h / max_send * 100) if max_send > 0 else 0,
            'provider': 'aws-ses-v2',
            'region': os.getenv('AWS_REGION', 'us-east-1'),
            'timestamp': datetime.utcnow().isoformat()
        }
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        raise Exception(f"AWS SES Error ({error_code}): {error_message}")

@mcp.tool
def get_account_send_enabled() -> Dict[str, Any]:
    """
    Check if sending is enabled for the AWS SES account.
    
    Returns:
        Dict with account sending status
    """
    try:
        ses_client = get_ses_client()
        
        response = ses_client.get_account()
        
        return {
            'sending_enabled': response.get('SendingEnabled', False),
            'enforcement_status': response.get('EnforcementStatus'),
            'production_access': response.get('ProductionAccessEnabled', False),
            'provider': 'aws-ses-v2',
            'region': os.getenv('AWS_REGION', 'us-east-1'),
            'timestamp': datetime.utcnow().isoformat()
        }
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        raise Exception(f"AWS SES Error ({error_code}): {error_message}")

# Suppression list management
@mcp.tool
def get_suppression_list(reason: Optional[str] = None) -> Dict[str, Any]:
    """
    Get emails in the suppression list (bounces, complaints).
    
    Args:
        reason: Filter by suppression reason ('BOUNCE' or 'COMPLAINT')
    
    Returns:
        Dict with suppressed email addresses
    """
    try:
        ses_client = get_ses_client()
        
        kwargs = {}
        if reason and reason in ['BOUNCE', 'COMPLAINT']:
            kwargs['Reasons'] = [reason]
        
        response = ses_client.list_suppressed_destinations(**kwargs)
        
        suppressed_emails = []
        for item in response.get('SuppressedDestinationSummaries', []):
            suppressed_emails.append({
                'email': item.get('EmailAddress'),
                'reason': item.get('Reason'),
                'last_update_time': item.get('LastUpdateTime')
            })
        
        return {
            'suppressed_emails': [item['email'] for item in suppressed_emails],
            'suppressed_details': suppressed_emails,
            'reason': reason or 'ALL',
            'count': len(suppressed_emails),
            'next_token': response.get('NextToken'),
            'provider': 'aws-ses-v2',
            'region': os.getenv('AWS_REGION', 'us-east-1'),
            'timestamp': datetime.utcnow().isoformat()
        }
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        raise Exception(f"AWS SES Error ({error_code}): {error_message}")

@mcp.tool
def add_to_suppression_list(emails: List[str], reason: str) -> Dict[str, Any]:
    """
    Add email addresses to the suppression list.
    
    Args:
        emails: List of email addresses to suppress
        reason: Reason for suppression ('BOUNCE' or 'COMPLAINT')
    
    Returns:
        Dict with results for each email
    """
    try:
        request = SuppressionRequest(emails=emails, reason=reason)
        
        ses_client = get_ses_client()
        results = []
        
        for email in request.emails:
            try:
                ses_client.put_suppressed_destination(
                    EmailAddress=email,
                    Reason=request.reason
                )
                
                results.append({
                    'email': email,
                    'success': True,
                    'reason': request.reason
                })
                
            except ClientError as e:
                results.append({
                    'email': email,
                    'success': False,
                    'error': f"{e.response['Error']['Code']}: {e.response['Error']['Message']}"
                })
        
        successful = [r for r in results if r['success']]
        
        return {
            'success': True,
            'results': results,
            'reason': request.reason,
            'total_emails': len(request.emails),
            'success_count': len(successful),
            'provider': 'aws-ses-v2',
            'region': os.getenv('AWS_REGION', 'us-east-1'),
            'timestamp': datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        raise Exception(f"Failed to add emails to suppression list: {str(e)}")

@mcp.tool
def remove_from_suppression_list(emails: List[str]) -> Dict[str, Any]:
    """
    Remove email addresses from the suppression list.
    
    Args:
        emails: List of email addresses to remove from suppression
    
    Returns:
        Dict with results for each email
    """
    try:
        request = SuppressionRequest(emails=emails)
        
        ses_client = get_ses_client()
        results = []
        
        for email in request.emails:
            try:
                ses_client.delete_suppressed_destination(EmailAddress=email)
                
                results.append({
                    'email': email,
                    'success': True,
                    'message': 'Removed from suppression list'
                })
                
            except ClientError as e:
                error_code = e.response['Error']['Code']
                
                if error_code == 'NotFoundException':
                    results.append({
                        'email': email,
                        'success': True,
                        'message': 'Email not in suppression list'
                    })
                else:
                    results.append({
                        'email': email,
                        'success': False,
                        'error': f"{error_code}: {e.response['Error']['Message']}"
                    })
        
        successful = [r for r in results if r['success']]
        
        return {
            'success': True,
            'results': results,
            'total_emails': len(request.emails),
            'success_count': len(successful),
            'provider': 'aws-ses-v2',
            'region': os.getenv('AWS_REGION', 'us-east-1'),
            'timestamp': datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        raise Exception(f"Failed to remove emails from suppression list: {str(e)}")

# Health check and server info
@mcp.tool
def health_check() -> Dict[str, Any]:
    """
    Check server health and AWS SES connectivity.
    
    Returns:
        Dict with health status and server information
    """
    try:
        # Test AWS SES connectivity
        ses_client = get_ses_client()
        
        # Try to get account info to verify connectivity
        account_response = ses_client.get_account()
        
        return {
            'status': 'healthy',
            'aws_ses_connected': True,
            'sending_enabled': account_response.get('SendingEnabled', False),
            'production_access': account_response.get('ProductionAccessEnabled', False),
            'provider': 'aws-ses-v2',
            'region': os.getenv('AWS_REGION', 'us-east-1'),
            'fastmcp_version': '2.0',
            'timestamp': datetime.utcnow().isoformat()
        }
        
    except NoCredentialsError:
        return {
            'status': 'unhealthy',
            'aws_ses_connected': False,
            'error': 'AWS credentials not configured',
            'provider': 'aws-ses-v2',
            'region': os.getenv('AWS_REGION', 'us-east-1'),
            'fastmcp_version': '2.0',
            'timestamp': datetime.utcnow().isoformat()
        }
    except Exception as e:
        return {
            'status': 'unhealthy',
            'aws_ses_connected': False,
            'error': str(e),
            'provider': 'aws-ses-v2',
            'region': os.getenv('AWS_REGION', 'us-east-1'),
            'fastmcp_version': '2.0',
            'timestamp': datetime.utcnow().isoformat()
        }

if __name__ == "__main__":
    # Run the FastMCP server
    mcp.run()