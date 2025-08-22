#!/usr/bin/env python3
# Auto-generated provider detection functions
# Generated on: 2025-08-22 00:25:20

from typing import Optional


def detect_provider_from_subdomain(subdomain: str) -> Optional[str]:
    """
    Detecta proveedor basado en subdomain usando patrones actualizados de Neo4j
    
    Returns:
        Provider ID if detected, None otherwise
    """
    subdomain_lower = subdomain.lower()
    
    # AWS patterns
    if any(pattern in subdomain_lower for pattern in ['amazonaws.com', 'aws.amazon.com', 'ec2', 's3']):
        return 'amazon'
    
    # Google patterns  
    if any(pattern in subdomain_lower for pattern in ['googleapis.com', 'googleusercontent.com', 'gstatic.com', 'google.com']):
        return 'google'
    
    # Microsoft patterns
    if any(pattern in subdomain_lower for pattern in ['azure.com', 'azurewebsites.net', 'outlook.com', 'office.com']):
        return 'microsoft'
    
    # Cloudflare patterns
    if any(pattern in subdomain_lower for pattern in ['cloudflare.com', 'cloudflaressl.com']):
        return 'cloudflare'
    
    # GitHub patterns
    if any(pattern in subdomain_lower for pattern in ['github.com', 'githubusercontent.com', 'github.io']):
        return 'github'
    
    # Heroku patterns
    if any(pattern in subdomain_lower for pattern in ['heroku.com', 'herokuapp.com']):
        return 'heroku'
    
    # Salesforce patterns
    if any(pattern in subdomain_lower for pattern in ['salesforce.com', 'force.com']):
        return 'salesforce'
    
    # Fastly patterns
    if any(pattern in subdomain_lower for pattern in ['fastly.com', 'fastlylb.net']):
        return 'fastly'
    
    # DigitalOcean patterns
    if any(pattern in subdomain_lower for pattern in ['digitalocean.com', 'digitaloceanspaces.com']):
        return 'digitalocean'
    
    return None

