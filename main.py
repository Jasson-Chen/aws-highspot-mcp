import os
import subprocess
import sys
import time
import json
import uuid
import base64
import secrets
import hashlib
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from mcp.server.fastmcp import FastMCP
from amzn_req import AmznReq
import requests

def check_midway_auth():
    """Check ~/.midway for valid cookies"""
    midway_path = Path.home() / ".midway"
    
    # Check if ~/.midway exists and has cookies
    if not midway_path.exists() or not any(midway_path.iterdir()):
        return False
    
    # Check cookie validation using AmznReq
    try:
        ar = AmznReq()
        return ar.is_midway_authenticated()
    except Exception:
        return False

def get_cognito_tokens():
    """Get Cognito tokens for Highspot authentication"""
    try:
        ar = AmznReq()
        ar.set_mwinit_cookie()
        
        # Get config
        config_response = ar.requests("https://mentor.ai.aws.dev/aws-exports.json")
        config = config_response.json()
        
        # OAuth flow
        state = secrets.token_urlsafe(32)
        code_verifier = secrets.token_urlsafe(32)
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode('ascii')).digest()
        ).decode('ascii').rstrip('=')
        
        cognito_domain = f"https://{config['oauth']['domain']}"
        client_id = config['aws_user_pools_web_client_id']
        redirect_uri = config['oauth']['redirectSignIn']
        
        auth_params = {
            'redirect_uri': redirect_uri,
            'response_type': 'code',
            'client_id': client_id,
            'identity_provider': 'AmazonID',
            'scope': ' '.join(config['oauth']['scope']),
            'state': state,
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256'
        }
        
        # Follow OAuth redirects
        auth_response = ar.requests(f"{cognito_domain}/oauth2/authorize", params=auth_params, allow_redirects=False)
        
        current_response = auth_response
        for _ in range(10):  # Max 10 redirects
            if 'Location' not in current_response.headers:
                break
            next_url = current_response.headers['Location']
            current_response = ar.requests(next_url, allow_redirects=False)
            
            if redirect_uri.split('//')[1] in next_url and 'code=' in next_url:
                params = parse_qs(urlparse(next_url).query)
                auth_code = params['code'][0]
                break
        else:
            raise Exception("Failed to get authorization code")
        
        # Exchange code for tokens
        token_response = ar.requests(
            f"{cognito_domain}/oauth2/token",
            method="POST",
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            data={
                'grant_type': 'authorization_code',
                'client_id': client_id,
                'code': auth_code,
                'redirect_uri': redirect_uri,
                'code_verifier': code_verifier
            }
        )
        
        if token_response.status_code == 200:
            tokens = token_response.json()
            return tokens['id_token']
        else:
            raise Exception(f"Token exchange failed: {token_response.status_code}")
            
    except Exception as e:
        raise Exception(f"Authentication failed: {str(e)}")
    

def main():
    """Main entry point with MCP server"""
    # Create MCP server (always start, check auth per tool call)
    mcp = FastMCP("Highspot MCP Server")
    
    @mcp.tool()
    def get_highspot_info() -> str:
        """Get basic Highspot information"""
        if not check_midway_auth():
            return "❌ Authentication required. Please run 'mwinit -o' first to authenticate with Midway."
            # return run_mwinit()
        return "✅ Highspot MCP server is running with valid midway authentication"
    
    @mcp.tool()
    def search_highspot(query: str) -> str:
        """
        Search Highspot content.
        MUST keep the reference number inside the body of response, and relevant resources at the end of response.
        """
        if not check_midway_auth():
            return "❌ Authentication required. Please run 'mwinit -o' first to authenticate with Midway."
        
        try:
            # Initialize AmznReq for authenticated requests
            ar = AmznReq()
            ar.set_mwinit_cookie()
            
            # Get Highspot configuration
            config_response = ar.requests("https://mentor.ai.aws.dev/aws-exports.json")
            if config_response.status_code != 200:
                return f"❌ Failed to fetch Highspot configuration: {config_response.status_code}"
            
            config = config_response.json()
            api_endpoint = config['config']['api_endpoint']
            
            # Get authentication token
            id_token = get_cognito_tokens()
            
            # Get workspace ID for AWS Documentation
            workspaces_response = ar.requests(
                f"{api_endpoint}/v1/workspaces",
                headers={
                    'Authorization': f'Bearer {id_token}',
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                }
            )
            
            if workspaces_response.status_code != 200:
                return f"❌ Failed to fetch workspaces: {workspaces_response.status_code}"
            
            workspaces = workspaces_response.json().get('data', [])
            workspace_id = next((w.get('id') for w in workspaces if w.get('name') == 'Highspot'), None)
            
            if not workspace_id:
                return "❌ AWS Documentation workspace not found"
            
            # Perform search using chat/process endpoint
            session_id = str(uuid.uuid4())
            search_data = {
                "provider": "bedrock",
                "modelName": "anthropic.claude-3-5-sonnet-20241022-v2:0",
                "text": query,
                "sessionId": session_id,
                "workspaceId": workspace_id,
                "mode": "chain",
                "supervisor": False,
                "modelKwargs": {
                    "max_tokens": 100000,
                    "temperature": 0.7
                }
            }
            
            search_response = ar.requests(
                f"{api_endpoint}/v1/chat/process",
                method="POST",
                headers={
                    'Authorization': f'Bearer {id_token}',
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                json=search_data
            )
            
            if search_response.status_code != 200:
                return f"❌ Search failed: {search_response.status_code} - {search_response.text}"
            
            result = search_response.json()
            if result.get('ok'):
                response_text = result.get('data', {}).get('response', 'No response')
                return f"✅ Highspot search results for '{query}':\n\n{response_text}. MUST keep the reference number inside the body of response, and relevant resources at the end of response."
            else:
                return f"❌ Search error: {result.get('error', 'Unknown error')}"
                
        except Exception as e:
            return f"❌ Search failed with error: {str(e)}"
    
    # Start the server
    mcp.run()

if __name__ == "__main__":
    main()