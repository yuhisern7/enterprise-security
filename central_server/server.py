#!/usr/bin/env python3
"""
Central Threat Intelligence Server
Aggregates threats from all connected client nodes and distributes learning
"""

import os
import sys
import json
import time
import logging
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from flask_cors import CORS
from functools import wraps
import hashlib
import secrets
from collections import defaultdict

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# Configuration
CENTRAL_DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')
os.makedirs(CENTRAL_DATA_DIR, exist_ok=True)

GLOBAL_THREATS_FILE = os.path.join(CENTRAL_DATA_DIR, 'global_threats.json')
CLIENT_REGISTRY_FILE = os.path.join(CENTRAL_DATA_DIR, 'client_registry.json')
THREAT_PATTERNS_FILE = os.path.join(CENTRAL_DATA_DIR, 'threat_patterns.json')
API_KEYS_FILE = os.path.join(CENTRAL_DATA_DIR, 'api_keys.json')

# In-memory cache
global_threats = []
client_registry = {}
threat_patterns = defaultdict(int)
api_keys = {}

# Statistics
stats = {
    'total_threats_received': 0,
    'active_clients': 0,
    'last_sync_time': None,
    'threat_types': defaultdict(int)
}


def load_data():
    """Load all persistent data"""
    global global_threats, client_registry, threat_patterns, api_keys
    
    # Load global threats
    if os.path.exists(GLOBAL_THREATS_FILE):
        try:
            with open(GLOBAL_THREATS_FILE, 'r') as f:
                global_threats = json.load(f)
            logger.info(f"Loaded {len(global_threats)} global threats")
        except Exception as e:
            logger.error(f"Error loading global threats: {e}")
            global_threats = []
    
    # Load client registry
    if os.path.exists(CLIENT_REGISTRY_FILE):
        try:
            with open(CLIENT_REGISTRY_FILE, 'r') as f:
                client_registry = json.load(f)
            logger.info(f"Loaded {len(client_registry)} registered clients")
        except Exception as e:
            logger.error(f"Error loading client registry: {e}")
            client_registry = {}
    
    # Load threat patterns
    if os.path.exists(THREAT_PATTERNS_FILE):
        try:
            with open(THREAT_PATTERNS_FILE, 'r') as f:
                threat_patterns.update(json.load(f))
            logger.info(f"Loaded {len(threat_patterns)} threat patterns")
        except Exception as e:
            logger.error(f"Error loading threat patterns: {e}")
    
    # Load API keys
    if os.path.exists(API_KEYS_FILE):
        try:
            with open(API_KEYS_FILE, 'r') as f:
                api_keys.update(json.load(f))
            logger.info(f"Loaded {len(api_keys)} API keys")
        except Exception as e:
            logger.error(f"Error loading API keys: {e}")
            api_keys = {}
    
    # Generate master API key if not exists
    if 'master' not in api_keys:
        master_key = secrets.token_urlsafe(32)
        api_keys['master'] = {
            'key': master_key,
            'role': 'admin',
            'created': datetime.now().isoformat()
        }
        save_api_keys()
        logger.warning(f"Generated new master API key: {master_key}")
        logger.warning("SAVE THIS KEY - it will not be shown again!")


def save_data(data_type='all'):
    """Save persistent data"""
    try:
        if data_type in ['all', 'threats']:
            with open(GLOBAL_THREATS_FILE, 'w') as f:
                json.dump(global_threats[-10000:], f, indent=2)  # Keep last 10K threats
        
        if data_type in ['all', 'clients']:
            with open(CLIENT_REGISTRY_FILE, 'w') as f:
                json.dump(client_registry, f, indent=2)
        
        if data_type in ['all', 'patterns']:
            with open(THREAT_PATTERNS_FILE, 'w') as f:
                json.dump(dict(threat_patterns), f, indent=2)
        
    except Exception as e:
        logger.error(f"Error saving {data_type}: {e}")


def save_api_keys():
    """Save API keys to disk"""
    try:
        with open(API_KEYS_FILE, 'w') as f:
            json.dump(api_keys, f, indent=2)
    except Exception as e:
        logger.error(f"Error saving API keys: {e}")


def require_api_key(f):
    """Decorator to require valid API key"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        
        if not api_key:
            return jsonify({'error': 'API key required'}), 401
        
        # Check if key exists
        valid_key = None
        for client_id, key_data in api_keys.items():
            if key_data['key'] == api_key:
                valid_key = client_id
                break
        
        if not valid_key:
            logger.warning(f"Invalid API key attempted: {api_key[:10]}...")
            return jsonify({'error': 'Invalid API key'}), 403
        
        # Add client info to request
        request.client_id = valid_key
        request.client_role = api_keys[valid_key].get('role', 'client')
        
        return f(*args, **kwargs)
    
    return decorated_function


@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'version': '1.0.0',
        'timestamp': datetime.now().isoformat(),
        'stats': {
            'total_threats': len(global_threats),
            'active_clients': len([c for c in client_registry.values() if c.get('last_seen')]),
            'threat_patterns': len(threat_patterns)
        }
    })


@app.route('/api/v1/register', methods=['POST'])
def register_client():
    """Register a new client node"""
    data = request.json
    
    client_name = data.get('client_name')
    client_info = data.get('client_info', {})
    
    if not client_name:
        return jsonify({'error': 'client_name required'}), 400
    
    # Generate unique client ID
    client_id = hashlib.sha256(f"{client_name}_{time.time()}".encode()).hexdigest()[:16]
    
    # Generate API key for this client
    api_key = secrets.token_urlsafe(32)
    
    # Register client
    client_registry[client_id] = {
        'name': client_name,
        'info': client_info,
        'registered': datetime.now().isoformat(),
        'last_seen': datetime.now().isoformat(),
        'threats_submitted': 0
    }
    
    api_keys[client_id] = {
        'key': api_key,
        'role': 'client',
        'created': datetime.now().isoformat()
    }
    
    save_data('clients')
    save_api_keys()
    
    logger.info(f"Registered new client: {client_name} ({client_id})")
    
    return jsonify({
        'client_id': client_id,
        'api_key': api_key,
        'message': 'Registration successful. SAVE YOUR API KEY - it will not be shown again!'
    }), 201


@app.route('/api/v1/submit-threats', methods=['POST'])
@require_api_key
def submit_threats():
    """Receive threats from client nodes"""
    data = request.json
    threats = data.get('threats', [])
    
    if not threats:
        return jsonify({'error': 'No threats provided'}), 400
    
    client_id = request.client_id
    
    # Process each threat
    new_threats = 0
    for threat in threats:
        # Add metadata
        threat['client_id'] = client_id
        threat['received_at'] = datetime.now().isoformat()
        
        # Update threat patterns
        attack_type = threat.get('attack_type', 'unknown')
        threat_patterns[attack_type] += 1
        stats['threat_types'][attack_type] += 1
        
        # Add to global threats
        global_threats.append(threat)
        new_threats += 1
    
    # Update client stats
    if client_id in client_registry:
        client_registry[client_id]['last_seen'] = datetime.now().isoformat()
        client_registry[client_id]['threats_submitted'] = client_registry[client_id].get('threats_submitted', 0) + new_threats
    
    stats['total_threats_received'] += new_threats
    stats['last_sync_time'] = datetime.now().isoformat()
    
    # Save data periodically
    if len(global_threats) % 100 == 0:
        save_data()
    
    logger.info(f"Received {new_threats} threats from client {client_id}")
    
    return jsonify({
        'message': f'Received {new_threats} threats',
        'total_global_threats': len(global_threats)
    }), 200


@app.route('/api/v1/get-threats', methods=['GET'])
@require_api_key
def get_threats():
    """Get global threat feed for client nodes"""
    client_id = request.client_id
    
    # Get query parameters
    since = request.args.get('since')  # ISO timestamp
    limit = int(request.args.get('limit', 1000))
    attack_types = request.args.getlist('attack_type')
    
    # Filter threats
    filtered_threats = global_threats
    
    if since:
        try:
            since_dt = datetime.fromisoformat(since)
            filtered_threats = [
                t for t in filtered_threats 
                if datetime.fromisoformat(t.get('received_at', '2000-01-01')) > since_dt
            ]
        except ValueError:
            pass
    
    if attack_types:
        filtered_threats = [
            t for t in filtered_threats 
            if t.get('attack_type') in attack_types
        ]
    
    # Limit results
    filtered_threats = filtered_threats[-limit:]
    
    # Update client last seen
    if client_id in client_registry:
        client_registry[client_id]['last_seen'] = datetime.now().isoformat()
    
    logger.info(f"Sent {len(filtered_threats)} threats to client {client_id}")
    
    return jsonify({
        'threats': filtered_threats,
        'total': len(filtered_threats),
        'global_total': len(global_threats)
    }), 200


@app.route('/api/v1/threat-patterns', methods=['GET'])
@require_api_key
def get_threat_patterns():
    """Get aggregated threat patterns"""
    return jsonify({
        'patterns': dict(threat_patterns),
        'total_patterns': len(threat_patterns),
        'total_threats': len(global_threats)
    }), 200


@app.route('/api/v1/stats', methods=['GET'])
@require_api_key
def get_stats():
    """Get central server statistics"""
    
    # Calculate active clients (seen in last 24 hours)
    cutoff = datetime.now() - timedelta(hours=24)
    active_clients = sum(
        1 for c in client_registry.values()
        if c.get('last_seen') and datetime.fromisoformat(c['last_seen']) > cutoff
    )
    
    return jsonify({
        'total_threats': len(global_threats),
        'total_clients': len(client_registry),
        'active_clients': active_clients,
        'threat_types': dict(stats['threat_types']),
        'last_sync': stats['last_sync_time'],
        'uptime': datetime.now().isoformat()
    }), 200


@app.route('/api/v1/clients', methods=['GET'])
@require_api_key
def list_clients():
    """List all registered clients (admin only)"""
    if request.client_role != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    
    # Remove sensitive info
    safe_registry = {}
    for client_id, info in client_registry.items():
        safe_registry[client_id] = {
            'name': info.get('name'),
            'registered': info.get('registered'),
            'last_seen': info.get('last_seen'),
            'threats_submitted': info.get('threats_submitted', 0)
        }
    
    return jsonify({
        'clients': safe_registry,
        'total': len(safe_registry)
    }), 200


@app.route('/api/v1/admin/reset-key/<client_id>', methods=['POST'])
@require_api_key
def reset_client_key(client_id):
    """Reset API key for a client (admin only)"""
    if request.client_role != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    
    if client_id not in client_registry:
        return jsonify({'error': 'Client not found'}), 404
    
    # Generate new API key
    new_key = secrets.token_urlsafe(32)
    api_keys[client_id]['key'] = new_key
    api_keys[client_id]['updated'] = datetime.now().isoformat()
    
    save_api_keys()
    
    return jsonify({
        'client_id': client_id,
        'new_api_key': new_key,
        'message': 'API key reset successful'
    }), 200


@app.route('/', methods=['GET'])
def index():
    """Central server status page"""
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Central Threat Intelligence Server</title>
        <style>
            body {{ font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }}
            h1 {{ color: #333; }}
            .stat {{ background: #f4f4f4; padding: 15px; margin: 10px 0; border-radius: 5px; }}
            .stat strong {{ color: #0066cc; }}
            code {{ background: #333; color: #0f0; padding: 2px 6px; border-radius: 3px; }}
        </style>
    </head>
    <body>
        <h1>🛡️ Central Threat Intelligence Server</h1>
        <div class="stat"><strong>Status:</strong> Online</div>
        <div class="stat"><strong>Global Threats:</strong> {len(global_threats)}</div>
        <div class="stat"><strong>Registered Clients:</strong> {len(client_registry)}</div>
        <div class="stat"><strong>Threat Patterns:</strong> {len(threat_patterns)}</div>
        
        <h2>API Endpoints</h2>
        <p><code>POST /api/v1/register</code> - Register new client</p>
        <p><code>POST /api/v1/submit-threats</code> - Submit threats (requires API key)</p>
        <p><code>GET /api/v1/get-threats</code> - Get global threat feed (requires API key)</p>
        <p><code>GET /api/v1/threat-patterns</code> - Get threat patterns (requires API key)</p>
        <p><code>GET /api/v1/stats</code> - Get statistics (requires API key)</p>
        
        <h2>Security</h2>
        <p>All API endpoints require HTTPS and API key authentication.</p>
        <p>Use <code>X-API-Key</code> header for authentication.</p>
    </body>
    </html>
    """


if __name__ == '__main__':
    logger.info("Starting Central Threat Intelligence Server...")
    
    # Load data
    load_data()
    
    # Get SSL configuration
    use_ssl = os.getenv('USE_SSL', 'true').lower() == 'true'
    
    if use_ssl:
        ssl_cert = os.getenv('SSL_CERT', 'certs/cert.pem')
        ssl_key = os.getenv('SSL_KEY', 'certs/key.pem')
        
        if os.path.exists(ssl_cert) and os.path.exists(ssl_key):
            logger.info("Starting with SSL enabled")
            app.run(
                host='0.0.0.0',
                port=5001,
                ssl_context=(ssl_cert, ssl_key),
                debug=False
            )
        else:
            logger.warning("SSL certificates not found, starting without SSL")
            app.run(host='0.0.0.0', port=5001, debug=False)
    else:
        logger.info("Starting without SSL (development mode)")
        app.run(host='0.0.0.0', port=5001, debug=False)
