#!/usr/bin/env python3
"""
FastMCP v2 AWS SES Email Server with Authentication
Production-ready deployment with OAuth/JWT authentication.
"""

import os
from typing import Dict, Any, Optional
from fastmcp import FastMCP
from fastmcp.auth import RemoteAuthProvider, TokenVerifier
from dotenv import load_dotenv

# Import our main server
from aws_ses_server import mcp as base_mcp

# Load environment variables
load_dotenv()

def create_authenticated_server() -> FastMCP:
    """Create FastMCP server with authentication enabled"""
    
    auth_type = os.getenv('MCP_AUTH_TYPE', 'none').lower()
    
    if auth_type == 'none':
        print("Running server without authentication (development mode)")
        return base_mcp
    
    elif auth_type == 'jwt':
        print("Setting up JWT token verification...")
        
        # JWT Token verification setup
        token_verifier = TokenVerifier(
            jwks_url=os.getenv('MCP_JWKS_URL'),
            issuer=os.getenv('MCP_JWT_ISSUER'),
            audience=os.getenv('MCP_JWT_AUDIENCE')
        )
        
        # Create authenticated MCP server
        auth_mcp = FastMCP(
            name="Authenticated AWS SES Email Server",
            description="Production AWS SES server with JWT authentication",
            auth_provider=token_verifier
        )
        
        # Copy all tools from base server
        auth_mcp._tools = base_mcp._tools.copy()
        
        return auth_mcp
    
    elif auth_type == 'oauth':
        print("Setting up OAuth authentication...")
        
        # OAuth setup
        oauth_provider = RemoteAuthProvider(
            client_id=os.getenv('MCP_CLIENT_ID'),
            client_secret=os.getenv('MCP_CLIENT_SECRET'),
            token_url=os.getenv('MCP_TOKEN_URL'),
            auth_url=os.getenv('MCP_AUTH_URL'),
            scopes=os.getenv('MCP_AUTH_SCOPES', 'email:send,email:manage').split(',')
        )
        
        # Create authenticated MCP server
        auth_mcp = FastMCP(
            name="Authenticated AWS SES Email Server",
            description="Production AWS SES server with OAuth authentication",
            auth_provider=oauth_provider
        )
        
        # Copy all tools from base server
        auth_mcp._tools = base_mcp._tools.copy()
        
        return auth_mcp
    
    else:
        raise ValueError(f"Unsupported authentication type: {auth_type}")

def main():
    """Main entry point for authenticated server"""
    
    # Create server with appropriate authentication
    server = create_authenticated_server()
    
    # Server configuration
    host = os.getenv('MCP_HOST', '0.0.0.0')
    port = int(os.getenv('MCP_PORT', 8000))
    debug = os.getenv('MCP_DEBUG', 'false').lower() == 'true'
    
    print(f"Starting FastMCP v2 AWS SES Server...")
    print(f"Host: {host}")
    print(f"Port: {port}")
    print(f"Debug: {debug}")
    print(f"AWS Region: {os.getenv('AWS_REGION', 'us-east-1')}")
    print(f"Authentication: {os.getenv('MCP_AUTH_TYPE', 'none')}")
    
    # Run the server
    server.run(host=host, port=port, debug=debug)

if __name__ == "__main__":
    main()