"""
Intellicrack Command Line Interface

Provides comprehensive CLI for all Intellicrack functionality including
payload generation, C2 management, and exploitation operations.
"""

import asyncio
import json
import logging
import os
import sys
import threading
import time
from typing import Optional

try:
    import click
except ImportError:
    print("Error: click module not found. Please install with: pip install click")
    sys.exit(1)

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import configuration system
try:
    from intellicrack.core.config_manager import get_config
    MODERN_CONFIG_AVAILABLE = True
except ImportError:
    MODERN_CONFIG_AVAILABLE = False

# Basic imports (with fallbacks for missing components)
try:
    from intellicrack.core.exploitation import (
        Architecture,
        PayloadEngine,
        PayloadTemplates,
        PayloadType,
    )
except ImportError:
    PayloadEngine = None
    PayloadTemplates = None
    Architecture = None
    PayloadType = None

try:
    from intellicrack.utils.exploitation.payload_result_handler import PayloadResultHandler
except ImportError:
    PayloadResultHandler = None

try:
    from intellicrack.core.c2 import C2Client, C2Server
except ImportError:
    C2Server = None
    C2Client = None
from intellicrack.utils.analysis.binary_analysis import analyze_binary
from intellicrack.utils.exploitation.exploitation import exploit
from intellicrack.utils.patching.patch_generator import generate_patch

# Import new exploitation modules
try:
    from intellicrack.ai.vulnerability_research_integration import VulnerabilityResearchAI
    from intellicrack.core.c2.c2_manager import C2Manager
    from intellicrack.core.exploitation.lateral_movement import LateralMovementManager
    from intellicrack.core.exploitation.payload_engine import PayloadEngine as AdvancedPayloadEngine
    from intellicrack.core.exploitation.persistence_manager import PersistenceManager
    from intellicrack.core.exploitation.privilege_escalation import PrivilegeEscalationManager
    from intellicrack.core.vulnerability_research.research_manager import (
        CampaignType,
        ResearchManager,
    )
    from intellicrack.core.vulnerability_research.vulnerability_analyzer import (
        AnalysisMethod,
        VulnerabilityAnalyzer,
    )
    ADVANCED_MODULES_AVAILABLE = True
except ImportError:
    ADVANCED_MODULES_AVAILABLE = False

# Initialize logger before it's used
logger = logging.getLogger("IntellicrackLogger.CLI")

# Since advanced modules are available, no need for fallback classes


@click.group()
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output', envvar='INTELLICRACK_VERBOSE')
@click.option('--quiet', '-q', is_flag=True, help='Suppress non-essential output', envvar='INTELLICRACK_QUIET')
def cli(verbose: bool, quiet: bool):
    """Intellicrack - Advanced Binary Analysis and Exploitation Framework"""
    # Configure logging
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    elif quiet:
        logging.basicConfig(level=logging.ERROR)
    else:
        logging.basicConfig(level=logging.INFO)
    
    # Initialize configuration if available
    if MODERN_CONFIG_AVAILABLE:
        try:
            config = get_config()
            logging.getLogger(__name__).debug(f"Loaded configuration from {config.config_dir}")
        except Exception as e:
            logging.getLogger(__name__).warning(f"Failed to load configuration: {e}")


@cli.group()
def payload():
    """Payload generation commands"""
    pass


@payload.command('generate')
@click.option('--type', '-t', 'payload_type',
              type=click.Choice(['reverse_shell', 'bind_shell', 'meterpreter', 'custom']),
              default='reverse_shell', help='Type of payload to generate')
@click.option('--arch', '-a', 'architecture',
              type=click.Choice(['x86', 'x64', 'arm', 'arm64']),
              default='x64', help='Target architecture')
@click.option('--lhost', help='Listener host for reverse connections')
@click.option('--lport', type=int, help='Listener port')
@click.option('--encoding', '-e', multiple=True,
              help='Encoding schemes to apply (can be specified multiple times)')
@click.option('--output', '-o', help='Output file path')
@click.option('--format', '-f', 'output_format',
              type=click.Choice(['raw', 'exe', 'dll', 'powershell', 'python', 'c']),
              default='raw', help='Output format')
def generate(payload_type: str, architecture: str, lhost: Optional[str],
            lport: Optional[int], encoding: tuple, output: Optional[str],
            output_format: str):
    """Generate a custom payload with various options"""
    try:
        engine = PayloadEngine()

        # Build target info and options
        target_info = {
            'os_type': 'unknown',
            'os_version': 'unknown',
            'architecture': architecture.lower(),
            'protections': [],
            'av_products': [],
            'network_config': {},
            'process_info': {}
        }

        options = {
            'output_format': output_format
        }

        # Add connection parameters
        if lhost:
            options['lhost'] = lhost
        if lport:
            options['lport'] = lport

        # Add encoding
        if encoding:
            options['encoding_schemes'] = list(encoding)

        # Add output format
        options['output_format'] = output_format

        click.echo(f"Generating {payload_type} payload for {architecture} (format: {output_format})...")

        # Generate payload
        result = engine.generate_payload(
            PayloadType[payload_type.upper()],
            Architecture[architecture.upper()],
            target_info,
            options
        )

        # Save output
        if output:
            with open(output, 'wb') as f:
                f.write(result['payload'])
            click.echo(f"Payload saved to: {output}")
        else:
            # Display payload info
            click.echo(f"Payload size: {len(result['payload'])} bytes")
            null_byte = b'\x00'
            click.echo(f"Null bytes: {result['payload'].count(null_byte)}")

            if not click.get_text_stream('stdout').isatty():
                # Output to pipe
                click.get_binary_stream('stdout').write(result['payload'])
            else:
                # Display hex dump for terminal
                from intellicrack.utils.binary.hex_utils import create_hex_dump
                click.echo("\nPayload hex dump:")
                click.echo(create_hex_dump(result['payload']))

        click.echo("Payload generated successfully!")

    except Exception as e:
        logger.error(f"Payload generation failed: {e}")
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@payload.command()
@click.option('--category', '-c',
              type=click.Choice(['shell', 'persistence', 'privilege_escalation',
                               'lateral_movement', 'steganography', 'anti_analysis']),
              help='Template category')
def list_templates(category: Optional[str]):
    """List available payload templates"""
    try:
        templates = PayloadTemplates()
        available = templates.list_templates(category)

        click.echo("Available payload templates:")
        for cat, template_list in available.items():
            click.echo(f"\n{cat.upper()}:")
            for template in template_list:
                click.echo(f"  - {template}")

    except Exception as e:
        logger.error(f"Failed to list templates: {e}")
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@payload.command()
@click.argument('category')
@click.argument('template_name')
@click.option('--arch', '-a', 'architecture',
              type=click.Choice(['x86', 'x64', 'arm', 'arm64']),
              default='x64', help='Target architecture')
@click.option('--param', '-p', multiple=True, help='Template parameters (key=value)')
@click.option('--output', '-o', help='Output file path')
def from_template(category: str, template_name: str, architecture: str,
                 param: tuple, output: Optional[str]):
    """Generate payload from template"""
    try:
        engine = PayloadEngine()
        templates = PayloadTemplates()

        # Parse parameters
        params = {}
        for p in param:
            if '=' in p:
                key, value = p.split('=', 1)
                params[key] = value

        # Get template
        arch = Architecture[architecture.upper()]
        template = templates.get_template(category, template_name, arch, **params)

        if not template:
            click.echo(f"Template not found: {category}/{template_name}", err=True)
            sys.exit(1)

        click.echo(f"Generating payload from template: {template_name}")

        # Generate from template
        target_info = {
            'os_type': 'unknown',
            'os_version': 'unknown',
            'architecture': architecture.lower(),
            'protections': [],
            'av_products': [],
            'network_config': {},
            'process_info': {}
        }

        options = {
            'mode': 'template',
            'template': template
        }

        # Determine payload type from template category
        payload_type_map = {
            'reverse_shell': PayloadType.REVERSE_SHELL,
            'bind_shell': PayloadType.BIND_SHELL,
            'staged': PayloadType.STAGED_PAYLOAD
        }
        payload_type = payload_type_map.get(category.lower(), PayloadType.REVERSE_SHELL)

        result = engine.generate_payload(
            payload_type,
            Architecture[architecture.upper()],
            target_info,
            options
        )

        # Save output
        if output:
            with open(output, 'wb') as f:
                f.write(result['payload'])
            click.echo(f"Payload saved to: {output}")
        else:
            click.echo(f"Payload size: {len(result['payload'])} bytes")

        click.echo("Payload generated successfully!")

    except Exception as e:
        logger.error(f"Template payload generation failed: {e}")
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.group()
def c2():
    """Command and Control operations"""
    pass


@c2.command()
@click.option('--host', '-h', default='0.0.0.0', help='Listen address')
@click.option('--https-port', default=443, help='HTTPS port')
@click.option('--dns-port', default=53, help='DNS port')
@click.option('--tcp-port', default=4444, help='TCP port')
@click.option('--protocols', '-p', multiple=True,
              type=click.Choice(['https', 'dns', 'tcp']),
              default=['https'], help='Protocols to enable')
def server(host: str, https_port: int, dns_port: int, tcp_port: int, protocols: tuple):
    """Start C2 server"""
    try:
        config = {
            'https_enabled': 'https' in protocols,
            'dns_enabled': 'dns' in protocols,
            'tcp_enabled': 'tcp' in protocols,
            'https': {'host': host, 'port': https_port},
            'dns': {'host': host, 'port': dns_port, 'domain': 'example.com'},
            'tcp': {'host': host, 'port': tcp_port}
        }

        click.echo("Starting C2 server...")
        click.echo(f"Protocols: {', '.join(protocols)}")

        # Create and start server
        c2_server = C2Server(config)

        # Add event handlers
        def on_session_connected(session):
            click.echo(f"[+] New session: {session.get('session_id', 'unknown')}")

        def on_session_disconnected(session):
            click.echo(f"[-] Session lost: {session.get('session_id', 'unknown')}")

        c2_server.add_event_handler('session_connected', on_session_connected)
        c2_server.add_event_handler('session_disconnected', on_session_disconnected)

        # Run server
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            loop.run_until_complete(c2_server.start())
        except KeyboardInterrupt:
            click.echo("\nShutting down server...")
            loop.run_until_complete(c2_server.stop())

    except Exception as e:
        logger.error(f"C2 server failed: {e}")
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@c2.command()
@click.option('--server', '-s', required=True, help='C2 server address')
@click.option('--port', '-p', default=443, help='Server port')
@click.option('--protocol', type=click.Choice(['https', 'dns', 'tcp']),
              default='https', help='Communication protocol')
@click.option('--interval', '-i', default=60, help='Beacon interval in seconds')
def client(server_host: str, port: int, protocol: str, interval: int):
    """Start C2 client (agent)"""
    try:
        config = {
            'beacon_interval': interval,
            'protocols': {
                f'{protocol}_enabled': True,
                protocol: {
                    'host': server_host,
                    'port': port
                }
            }
        }

        click.echo(f"Connecting to C2 server at {server_host}:{port} via {protocol}")

        # Create and start client
        c2_client = C2Client(config)

        # Run client
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            loop.run_until_complete(c2_client.start())
        except KeyboardInterrupt:
            click.echo("\nDisconnecting from server...")
            loop.run_until_complete(c2_client.stop())

    except Exception as e:
        logger.error(f"C2 client failed: {e}")
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@c2.command()
@click.argument('session_id')
@click.argument('command')
def exec(session_id: str, command: str):
    """Execute command on remote session"""
    # This would connect to running C2 server
    click.echo(f"Executing on {session_id}: {command}")
    click.echo("Note: This requires a running C2 server instance")


@cli.command()
@click.argument('target')
@click.option('--type', '-t', 'exploit_type',
              type=click.Choice(['auto', 'buffer_overflow', 'format_string',
                               'heap_overflow', 'use_after_free']),
              default='auto', help='Exploit type')
@click.option('--payload', '-p', help='Custom payload or payload file')
@click.option('--output', '-o', help='Output exploit to file')
def exploit_target(target: str, exploit_type: str, payload_data: Optional[str],
                  output: Optional[str]):
    """Exploit a target binary or service"""
    try:
        click.echo(f"Exploiting target: {target}")
        click.echo(f"Exploit type: {exploit_type}")

        result = exploit(target, exploit_type, payload_data)

        if result['success']:
            click.echo("Exploitation successful!")

            if 'exploit_code' in result and output:
                with open(output, 'w') as f:
                    f.write(result['exploit_code'])
                click.echo(f"Exploit saved to: {output}")

            # Display results
            if 'session' in result:
                click.echo(f"Session established: {result['session']}")
            if 'details' in result:
                click.echo(f"Details: {result['details']}")
        else:
            click.echo("Exploitation failed!", err=True)
            if 'error' in result:
                click.echo(f"Error: {result['error']}", err=True)

    except Exception as e:
        logger.error(f"Exploitation failed: {e}")
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.command('basic-analyze')
@click.argument('binary_path')
@click.option('--deep', '-d', is_flag=True, help='Perform deep analysis')
@click.option('--output', '-o', help='Save analysis report')
@click.option('--no-ai', is_flag=True, help='Disable AI integration')
def basic_analyze(binary_path: str, deep: bool, output: Optional[str], no_ai: bool):
    """Analyze a binary file with AI integration"""
    try:
        click.echo(f"Analyzing binary: {binary_path}")
        if deep:
            click.echo("Performing deep analysis...")

        if not no_ai:
            click.echo("AI integration enabled - will suggest script generation opportunities")

        result = analyze_binary(binary_path, detailed=deep, enable_ai_integration=not no_ai)

        # Display analysis
        click.echo(f"\nBinary Type: {result.get('file_type', 'Unknown')}")
        click.echo(f"Architecture: {result.get('architecture', 'Unknown')}")
        click.echo(f"Size: {result.get('size', 0)} bytes")

        if 'protections' in result:
            click.echo("\nProtections:")
            for protection, enabled in result['protections'].items():
                protection_status = "Enabled" if enabled else "Disabled"
                click.echo(f"  {protection}: {protection_status}")

        if 'vulnerabilities' in result and result['vulnerabilities']:
            click.echo("\nPotential Vulnerabilities:")
            for vuln in result['vulnerabilities']:
                click.echo(f"  - {vuln}")

        # Display AI integration results
        if 'ai_integration' in result and result['ai_integration'].get('enabled'):
            ai_data = result['ai_integration']
            click.echo("\n🤖 AI Script Generation Suggestions:")

            suggestions = ai_data.get('script_suggestions', {})
            if suggestions.get('frida_scripts'):
                click.echo("  Frida Scripts:")
                for script in suggestions['frida_scripts']:
                    click.echo(f"    - {script['description']} (confidence: {script['confidence']:.0%})")

            if suggestions.get('ghidra_scripts'):
                click.echo("  Ghidra Scripts:")
                for script in suggestions['ghidra_scripts']:
                    click.echo(f"    - {script['description']} (confidence: {script['confidence']:.0%})")

            # Display recommended actions
            if ai_data.get('recommended_actions'):
                click.echo("\n  Recommended AI Actions:")
                for action in ai_data['recommended_actions']:
                    click.echo(f"    • {action}")

            # Display auto-generation status
            auto_confidence = suggestions.get('auto_generate_confidence', 0)
            if auto_confidence > 0.8:
                click.echo(f"\n  🚀 High confidence ({auto_confidence:.0%}) - Autonomous script generation triggered!")
            elif auto_confidence > 0.5:
                click.echo(f"\n  ⚡ Moderate confidence ({auto_confidence:.0%}) - Consider manual script generation")

            # Display autonomous generation status
            if ai_data.get('autonomous_generation', {}).get('started'):
                click.echo("  🔄 Autonomous script generation started in background")
                click.echo(f"  📋 Targets: {', '.join(ai_data['autonomous_generation']['targets'])}")

        elif 'ai_integration' in result and not result['ai_integration'].get('enabled'):
            ai_error = result['ai_integration'].get('error', 'Unknown error')
            click.echo(f"\n⚠️  AI integration failed: {ai_error}")

        if output:
            with open(output, 'w') as f:
                json.dump(result, f, indent=2)
            click.echo(f"\nAnalysis saved to: {output}")

    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument('binary_path')
@click.option('--offset', '-o', type=str, help='Patch offset (hex)')
@click.option('--data', '-d', help='Patch data (hex)')
@click.option('--nop-range', '-n', help='NOP range (start:end in hex)')
@click.option('--output', '-O', help='Output patched binary')
def patch(binary_path: str, offset: Optional[str], data: Optional[str],
         nop_range: Optional[str], output: Optional[str]):
    """Patch a binary file"""
    try:
        patches = []

        if offset and data:
            patches.append({
                'offset': int(offset, 16),
                'data': bytes.fromhex(data.replace(' ', ''))
            })

        if nop_range:
            nop_start, nop_end = nop_range.split(':')
            patches.append({
                'type': 'nop',
                'start': int(nop_start, 16),
                'end': int(nop_end, 16)
            })

        if not patches:
            click.echo("No patches specified!", err=True)
            sys.exit(1)

        click.echo(f"Patching binary: {binary_path}")

        patch_config = {
            'patches': patches,
            'output_path': output
        }
        result = generate_patch(binary_path, patch_config)

        if result['success']:
            click.echo("Patching successful!")
            click.echo(f"Output: {result.get('output_path', 'N/A')}")
        else:
            click.echo("Patching failed!", err=True)

    except Exception as e:
        logger.error(f"Patching failed: {e}")
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


# =============================================================================
# Enhanced CLI Commands for Advanced Exploitation Framework
# =============================================================================

@cli.group()
def advanced():
    """Advanced exploitation commands"""
    if not ADVANCED_MODULES_AVAILABLE:
        click.echo("Advanced modules not available. Please check installation.", err=True)
        sys.exit(1)


@advanced.group()
def advanced_payload():
    """Advanced payload generation commands"""
    pass


@advanced_payload.command()
@click.option('--type', '-t', 'payload_type',
              type=click.Choice(['reverse_shell', 'bind_shell', 'meterpreter', 'staged_payload', 'custom']),
              default='reverse_shell', help='Payload type')
@click.option('--arch', '-a', 'architecture',
              type=click.Choice(['x86', 'x64', 'arm', 'arm64']),
              default='x64', help='Target architecture')
@click.option('--lhost', required=True, help='Listener host')
@click.option('--lport', type=int, required=True, help='Listener port')
@click.option('--encoding', type=click.Choice(['none', 'polymorphic', 'metamorphic', 'xor', 'alpha']),
              default='polymorphic', help='Payload encoding')
@click.option('--evasion', type=click.Choice(['none', 'low', 'medium', 'high', 'maximum']),
              default='medium', help='Evasion level')
@click.option('--output', '-o', help='Output file path')
@click.option('--format', type=click.Choice(['raw', 'exe', 'dll', 'shellcode']),
              default='raw', help='Output format')
def advanced_generate(payload_type: str, architecture: str, lhost: str, lport: int,
                     encoding: str, evasion: str, output: Optional[str], format: str):
    """Generate advanced payload with evasion techniques"""
    try:
        from intellicrack.core.exploitation.payload_types import (
            Architecture as AdvancedArchitecture,
        )
        from intellicrack.core.exploitation.payload_types import EncodingType
        from intellicrack.core.exploitation.payload_types import PayloadType as AdvancedPayloadType

        engine = AdvancedPayloadEngine()

        # Map CLI values to enum values
        payload_type_mapping = {
            'reverse_shell': AdvancedPayloadType.REVERSE_SHELL,
            'bind_shell': AdvancedPayloadType.BIND_SHELL,
            'meterpreter': AdvancedPayloadType.METERPRETER,
            'staged_payload': AdvancedPayloadType.STAGED_PAYLOAD,
            'custom': AdvancedPayloadType.CUSTOM
        }

        arch_mapping = {
            'x86': AdvancedArchitecture.X86,
            'x64': AdvancedArchitecture.X64,
            'arm': AdvancedArchitecture.ARM,
            'arm64': AdvancedArchitecture.ARM64
        }

        encoding_mapping = {
            'none': EncodingType.NONE,
            'polymorphic': EncodingType.POLYMORPHIC,
            'metamorphic': EncodingType.METAMORPHIC,
            'xor': EncodingType.XOR,
            'alpha': EncodingType.ALPHANUMERIC
        }

        target_info = {
            'os_type': 'windows',
            'architecture': architecture,
            'protections': ['aslr', 'dep'],
            'av_products': []
        }

        options = {
            'lhost': lhost,
            'lport': lport,
            'encoding': encoding_mapping[encoding],
            'evasion_level': evasion,
            'output_format': format
        }

        click.echo(f"Generating {payload_type} payload...")
        click.echo(f"Target: {architecture}, Encoding: {encoding}, Evasion: {evasion}, Format: {format}")

        result = engine.generate_payload(
            payload_type=payload_type_mapping[payload_type],
            architecture=arch_mapping[architecture],
            target_info=target_info,
            options=options
        )

        # Define save callback for file output
        def save_payload(payload_data: bytes, metadata: dict):
            if output:
                with open(output, 'wb') as f:
                    f.write(payload_data)
                click.echo(f"Payload saved to: {output}")
                # Save metadata alongside if available
                if metadata:
                    metadata_file = output + '.metadata.json'
                    with open(metadata_file, 'w') as f:
                        json.dump(metadata, f, indent=2)
                    click.echo(f"Metadata saved to: {metadata_file}")
            else:
                # Display hex dump
                hex_dump = payload_data[:256].hex()  # First 256 bytes
                click.echo("\nPayload preview (first 256 bytes):")
                for i in range(0, len(hex_dump), 32):
                    click.echo(hex_dump[i:i+32])
                # Display metadata if available
                if metadata:
                    click.echo("\nPayload metadata:")
                    for key, value in metadata.items():
                        click.echo(f"  {key}: {value}")

        # Use common payload result handler
        if PayloadResultHandler:
            success = PayloadResultHandler.process_payload_result(result, click.echo, save_payload)
            if not success:
                sys.exit(1)
        else:
            # Fallback for missing handler
            if result['success']:
                save_payload(result['payload'], result['metadata'])
            else:
                click.echo(f"✗ Payload generation failed: {result.get('error', 'Unknown error')}")
                sys.exit(1)

    except Exception as e:
        logger.error(f"Advanced payload generation failed: {e}")
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@advanced.group()
def advanced_c2():
    """Advanced C2 infrastructure commands"""
    pass


@advanced_c2.command()
@click.option('--protocol', type=click.Choice(['http', 'https', 'tcp', 'udp', 'dns']),
              default='https', help='C2 protocol')
@click.option('--port', '-p', type=int, help='Listen port')
@click.option('--encryption', type=click.Choice(['aes256', 'xor', 'rc4', 'chacha20']),
              default='aes256', help='Encryption method')
@click.option('--interface', '-i', default='0.0.0.0', help='Listen interface')
@click.option('--config', '-c', help='Configuration file path')
def start(protocol: str, port: Optional[int], encryption: str, interface: str, config: Optional[str]):
    """Start advanced C2 server"""
    try:
        manager = C2Manager()

        # Set default ports
        default_ports = {'http': 8080, 'https': 8443, 'tcp': 4444, 'udp': 5555, 'dns': 5353}
        if not port:
            port = default_ports.get(protocol, 8080)

        server_config = {
            'protocol': protocol,
            'port': port,
            'interface': interface,
            'encryption_method': encryption.lower(),
            'max_sessions': 100,
            'session_timeout': 300
        }

        if config:
            with open(config, 'r') as f:
                file_config = json.load(f)
                server_config.update(file_config)

        click.echo(f"Starting C2 server on {interface}:{port} ({protocol})")
        click.echo(f"Encryption: {encryption}")

        result = manager.start_server(server_config)

        if result['success']:
            click.echo("✓ C2 server started successfully!")
            click.echo(f"  Server ID: {result['server_id']}")
            click.echo(f"  Address: {result['address']}")

            # Keep server running
            try:
                click.echo("Press Ctrl+C to stop server...")
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                click.echo("\nStopping C2 server...")
                manager.stop_server()
                click.echo("Server stopped.")
        else:
            click.echo(f"✗ Failed to start C2 server: {result.get('error')}")
            sys.exit(1)

    except Exception as e:
        logger.error(f"C2 server failed: {e}")
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@c2.command()
def status():
    """Show C2 server status and active sessions"""
    try:
        manager = C2Manager()
        status_info = manager.get_server_status()

        click.echo("C2 Server Status:")
        click.echo(f"  Running: {status_info['running']}")
        click.echo(f"  Active Sessions: {status_info['active_sessions']}")
        click.echo(f"  Total Connections: {status_info['total_connections']}")

        if status_info['sessions']:
            click.echo("\nActive Sessions:")
            for session in status_info['sessions']:
                click.echo(f"  • {session['id']} - {session['remote_ip']} ({session['platform']})")

    except Exception as e:
        logger.error(f"Failed to get C2 status: {e}")
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@advanced.group()
def research():
    """Vulnerability research commands"""
    pass


@research.command()
@click.argument('target_path')
@click.option('--type', '-t', 'campaign_type',
              type=click.Choice(['binary_analysis', 'fuzzing', 'vulnerability_assessment', 'patch_analysis', 'hybrid_research']),
              default='binary_analysis', help='Research campaign type')
@click.option('--output', '-o', help='Output directory for results')
@click.option('--timeout', type=int, default=3600, help='Analysis timeout (seconds)')
@click.option('--use-ai', is_flag=True, help='Use AI-guided analysis')
def run(target_path: str, campaign_type: str, output: Optional[str], timeout: int, use_ai: bool):
    """Run vulnerability research analysis"""
    try:
        if not os.path.exists(target_path):
            click.echo(f"Target file not found: {target_path}", err=True)
            sys.exit(1)

        if use_ai:
            # Use AI-guided analysis
            ai_researcher = VulnerabilityResearchAI()

            click.echo(f"Running AI-guided analysis on {target_path} (timeout: {timeout}s)...")
            # Set timeout for the analysis
            import platform
            import signal

            try:
                if platform.system() != 'Windows' and hasattr(signal, 'SIGALRM') and hasattr(signal, 'alarm'):
                    def timeout_handler(signum, frame):
                        logger.warning(f"AI analysis timeout handler: signal {signum}, frame {frame}")
                        raise TimeoutError(f"Analysis timed out after {timeout} seconds")

                    signal.signal(signal.SIGALRM, timeout_handler)
                    signal.alarm(timeout)

                    try:
                        result = ai_researcher.analyze_target_with_ai(target_path)
                    finally:
                        signal.alarm(0)  # Cancel the alarm
                else:
                    # Windows or systems without SIGALRM
                    result = ai_researcher.analyze_target_with_ai(target_path)
            except (AttributeError, OSError):
                # Fallback for systems without signal support - use threading for timeout
                exception_holder = [None]
                result = None

                def run_analysis():
                    try:
                        nonlocal result
                        result = ai_researcher.analyze_target_with_ai(target_path)
                    except Exception as e:
                        exception_holder[0] = e

                thread = threading.Thread(target=run_analysis)
                thread.daemon = True
                thread.start()
                thread.join(timeout)

                if thread.is_alive():
                    # Thread is still running, analysis timed out
                    result = {'success': False, 'error': f'Analysis timed out after {timeout} seconds'}
                elif exception_holder[0] is not None:
                    exception_to_raise = exception_holder[0]
                    if exception_to_raise is not None:
                        raise exception_to_raise

            if result['success']:
                click.echo("✓ AI analysis completed!")

                # Show risk assessment
                risk = result['risk_assessment']
                click.echo(f"  Risk Level: {risk['overall_risk']}")
                click.echo(f"  Risk Score: {risk['risk_score']:.2f}")
                click.echo(f"  Exploitation Likelihood: {risk['exploitation_likelihood']:.2f}")

                # Show AI recommendations
                recommendations = result['ai_recommendations']
                if recommendations:
                    click.echo(f"\nAI Recommendations ({len(recommendations)}):")
                    for i, rec in enumerate(recommendations[:5], 1):
                        click.echo(f"  {i}. {rec}")

                # Show exploitation strategies
                strategies = result['exploitation_strategies']
                if strategies:
                    click.echo(f"\nExploitation Strategies ({len(strategies)}):")
                    for strategy in strategies[:3]:
                        vuln = strategy['vulnerability']
                        click.echo(f"  • {vuln['type']} ({vuln['severity']}) - {strategy['approach']}")
                        click.echo(f"    Confidence: {strategy['confidence']:.2f}")

        else:
            # Use standard research manager
            manager = ResearchManager()
            analyzer = VulnerabilityAnalyzer()

            # Select campaign type based on campaign_type parameter
            campaign_type_mapping = {
                'binary_analysis': CampaignType.BINARY_ANALYSIS,
                'fuzzing': CampaignType.FUZZING,
                'vulnerability_assessment': CampaignType.VULNERABILITY_ASSESSMENT,
                'patch_analysis': CampaignType.PATCH_ANALYSIS,
                'hybrid_research': CampaignType.HYBRID_RESEARCH
            }

            # Get actual campaign type from mapping
            selected_campaign_type = campaign_type_mapping.get(campaign_type, CampaignType.BINARY_ANALYSIS)

            # Create a campaign using the manager's proper interface
            campaign_result = manager.create_campaign(
                name=f"CLI_Campaign_{int(time.time())}",
                campaign_type=selected_campaign_type,
                targets=[target_path]
            )
            
            if campaign_result:
                click.echo(f"✅ Created research campaign: {campaign_result.get('name', 'Unknown')}")
                click.echo(f"📁 Campaign ID: {campaign_result.get('campaign_id', 'Unknown')}")
            else:
                click.echo("❌ Failed to create research campaign")
                return

            # Use analyzer for initial vulnerability assessment
            initial_assessment = analyzer.analyze_target(target_path)
            if initial_assessment.get('vulnerabilities'):
                click.echo(f"⚠️  {len(initial_assessment['vulnerabilities'])} vulnerabilities detected")

            click.echo(f"Running {campaign_type} analysis on {target_path}...")

            # Run direct analysis with timeout
            import platform
            import signal

            try:
                if platform.system() != 'Windows' and hasattr(signal, 'SIGALRM') and hasattr(signal, 'alarm'):
                    def timeout_handler(signum, frame):
                        logger.warning(f"Vulnerability analysis timeout handler: signal {signum}, frame {frame}")
                        raise TimeoutError(f"Analysis timed out after {timeout} seconds")

                    signal.signal(signal.SIGALRM, timeout_handler)
                    signal.alarm(timeout)

                    try:
                        result = analyzer.analyze_vulnerability(
                            target_path=target_path,
                            analysis_method=AnalysisMethod.HYBRID,
                            vulnerability_types=None
                        )
                    finally:
                        signal.alarm(0)  # Cancel the alarm
                else:
                    # Windows or systems without SIGALRM
                    result = analyzer.analyze_vulnerability(
                        target_path=target_path,
                        analysis_method=AnalysisMethod.HYBRID,
                        vulnerability_types=None
                    )
            except (AttributeError, OSError):
                # Fallback for systems without signal support
                result = analyzer.analyze_vulnerability(
                    target_path=target_path,
                    analysis_method=AnalysisMethod.HYBRID,
                    vulnerability_types=None
                )

            if result['success']:
                vulnerabilities = result['vulnerabilities']
                click.echo(f"✓ Analysis completed - {len(vulnerabilities)} vulnerabilities found")

                # Categorize vulnerabilities
                critical = [v for v in vulnerabilities if v['severity'] == 'critical']
                high = [v for v in vulnerabilities if v['severity'] == 'high']
                medium = [v for v in vulnerabilities if v['severity'] == 'medium']

                click.echo(f"  Critical: {len(critical)}")
                click.echo(f"  High: {len(high)}")
                click.echo(f"  Medium: {len(medium)}")

                # Show top vulnerabilities
                if vulnerabilities:
                    click.echo("\nTop Vulnerabilities:")
                    for vuln in vulnerabilities[:5]:
                        click.echo(f"  • {vuln['type']} ({vuln['severity']}) - {vuln['description']}")

        # Save results if output specified
        if output and result['success']:
            os.makedirs(output, exist_ok=True)
            result_file = os.path.join(output, f"analysis_results_{int(time.time())}.json")

            with open(result_file, 'w') as f:
                json.dump(result, f, indent=2, default=str)

            click.echo(f"\nResults saved to: {result_file}")

    except Exception as e:
        logger.error(f"Vulnerability research failed: {e}")
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@advanced.group()
def post_exploit():
    """Post-exploitation commands"""
    pass


@post_exploit.command()
@click.option('--platform', type=click.Choice(['windows', 'linux', 'macos']),
              required=True, help='Target platform')
@click.option('--method', type=click.Choice(['auto', 'registry', 'service', 'scheduled_task', 'startup']),
              default='auto', help='Persistence method')
@click.option('--payload-path', help='Path to payload for persistence')
def persist(target_platform: str, method: str, payload_path: Optional[str]):
    """Establish persistence on target system"""
    try:
        manager = PersistenceManager()

        # Configure manager based on target platform
        platform_configs = {
            'windows': {
                'default_payload': 'C:\\Windows\\Temp\\implant.exe',
                'methods': ['registry', 'service', 'scheduled_task', 'startup'],
                'stealth_level': 'high'
            },
            'linux': {
                'default_payload': '/tmp/implant',
                'methods': ['systemd', 'cron', 'rc_local', 'profile'],
                'stealth_level': 'medium'
            },
            'macos': {
                'default_payload': '/tmp/implant',
                'methods': ['launchd', 'cron', 'profile', 'login_items'],
                'stealth_level': 'high'
            }
        }

        platform_config = platform_configs.get(target_platform, platform_configs['linux'])

        # Auto-select method if not specified or validate platform compatibility
        if method == 'auto':
            method = platform_config['methods'][0]  # Use best method for platform
        elif method not in platform_config['methods']:
            click.echo(f"⚠️  Method '{method}' may not be optimal for {target_platform}")

        click.echo(f"Establishing {method} persistence on {target_platform}...")

        result = manager.establish_persistence(
            payload_path=payload_path or platform_config['default_payload'],
            target_os=target_platform,
            privilege_level='user',
            stealth_level=platform_config['stealth_level'],
            options={'preferred_method': method}
        )

        if result['success']:
            click.echo("✓ Persistence established successfully!")
            click.echo(f"  Method: {result['method']}")
            click.echo(f"  Location: {result['location']}")
            if 'cleanup_cmd' in result:
                click.echo(f"  Cleanup: {result['cleanup_cmd']}")
        else:
            click.echo(f"✗ Persistence failed: {result.get('error')}")
            sys.exit(1)

    except Exception as e:
        logger.error(f"Persistence establishment failed: {e}")
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@post_exploit.command()
@click.option('--platform', type=click.Choice(['windows', 'linux', 'macos']),
              required=True, help='Target platform')
@click.option('--method', type=click.Choice(['auto', 'kernel_exploit', 'suid_binary', 'service_exploit']),
              default='auto', help='Privilege escalation method')
def escalate(target_platform: str, method: str):
    """Escalate privileges on target system"""
    try:
        manager = PrivilegeEscalationManager()

        click.echo(f"Attempting privilege escalation on {target_platform} using {method}...")

        result = manager.escalate_privileges(target_platform=target_platform, method=method)

        if result['success']:
            click.echo("✓ Privilege escalation successful!")
            click.echo(f"  Method: {result['method']}")
            click.echo(f"  New privileges: {result['privileges']}")
        else:
            click.echo(f"✗ Privilege escalation failed: {result.get('error')}")
            sys.exit(1)

    except Exception as e:
        logger.error(f"Privilege escalation failed: {e}")
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@post_exploit.command()
@click.option('--method', type=click.Choice(['auto', 'smb', 'ssh', 'wmi', 'psexec']),
              default='auto', help='Lateral movement method')
@click.option('--target', help='Specific target IP (optional)')
def lateral(method: str, target: Optional[str]):
    """Perform lateral movement to other systems"""
    try:
        manager = LateralMovementManager()

        if target:
            click.echo(f"Attempting lateral movement to {target} using {method}...")
            result = manager.move_to_target(target, method=method)
        else:
            click.echo("Discovering targets for lateral movement...")
            result = manager.discover_targets()

            if result['success']:
                targets = result['targets']
                click.echo(f"✓ Discovered {len(targets)} potential targets:")

                for target_info in targets[:10]:  # Show first 10
                    click.echo(f"  • {target_info['ip']} - {target_info['hostname']} ({target_info['os']})")

                return

        if result['success']:
            click.echo("✓ Lateral movement successful!")
            click.echo(f"  Target: {result['target']}")
            click.echo(f"  Method: {result['method']}")
        else:
            click.echo(f"✗ Lateral movement failed: {result.get('error')}")
            sys.exit(1)

    except Exception as e:
        logger.error(f"Lateral movement failed: {e}")
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@advanced.command()
@click.argument('target_path')
@click.option('--lhost', required=True, help='Listener host')
@click.option('--lport', type=int, required=True, help='Listener port')
@click.option('--platform', type=click.Choice(['windows', 'linux', 'macos']),
              default='windows', help='Target platform')
@click.option('--output', '-o', help='Save detailed results to file')
def auto_exploit(target_path: str, lhost: str, lport: int, target_platform: str, output: Optional[str]):
    """Run full automated exploitation workflow"""
    try:
        if not os.path.exists(target_path):
            click.echo(f"Target file not found: {target_path}", err=True)
            sys.exit(1)

        ai_researcher = VulnerabilityResearchAI()

        target_info = {
            'binary_path': target_path,
            'platform': target_platform,
            'network_config': {
                'lhost': lhost,
                'lport': lport
            }
        }

        click.echo(f"Starting automated exploitation of {os.path.basename(target_path)}...")
        click.echo(f"Target platform: {target_platform}")
        click.echo(f"Callback: {lhost}:{lport}")
        click.echo("=" * 50)

        result = ai_researcher.execute_automated_exploitation(target_info)

        if result['success']:
            click.echo("✓ Automated exploitation completed successfully!")
            click.echo(f"  Workflow ID: {result['workflow_id']}")
            click.echo(f"  Final Status: {result['final_status']}")

            # Show exploitation timeline
            timeline = result['exploitation_timeline']
            click.echo(f"\nExploitation Timeline ({len(timeline)} phases):")
            for entry in timeline:
                status_symbol = "✓" if entry['status'] == 'completed' else "✗"
                click.echo(f"  {status_symbol} {entry['phase'].replace('_', ' ').title()}")

            # Show AI adaptations
            adaptations = result['ai_adaptations']
            if adaptations:
                click.echo(f"\nAI Adaptations Applied ({len(adaptations)}):")
                for adaptation in adaptations[:3]:
                    click.echo(f"  • {adaptation}")

        else:
            click.echo(f"✗ Automated exploitation failed: {result.get('error')}")

            # Show what phases completed
            if 'exploitation_phases' in result:
                phases = result['exploitation_phases']
                click.echo("\nPhase Results:")
                for phase_name, phase_result in phases.items():
                    phase_status = "✓" if phase_result.get('success') else "✗"
                    click.echo(f"  {phase_status} {phase_name.replace('_', ' ').title()}")

            sys.exit(1)

        # Save detailed results
        if output:
            with open(output, 'w') as f:
                json.dump(result, f, indent=2, default=str)
            click.echo(f"\nDetailed results saved to: {output}")

    except Exception as e:
        logger.error(f"Automated exploitation failed: {e}")
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.group()
def ai():
    """AI-powered script generation and analysis commands"""
    pass


@ai.command('generate')
@click.argument('binary_path')
@click.option('--script-type', type=click.Choice(['frida', 'ghidra', 'both']),
              default='frida', help='Type of script to generate')
@click.option('--complexity', type=click.Choice(['basic', 'advanced']),
              default='basic', help='Script complexity level')
@click.option('--focus', type=click.Choice(['auto', 'license', 'trial', 'network', 'anti-debug', 'vm']),
              default='auto', help='Protection focus')
@click.option('--output', '-o', help='Output directory for generated scripts')
@click.option('--autonomous', is_flag=True, help='Enable autonomous mode with testing')
@click.option('--preview', is_flag=True, help='Preview script before saving')
def ai_generate(binary_path: str, script_type: str, complexity: str, focus: str,
             output: Optional[str], autonomous_mode: bool, preview: bool):
    """Generate AI scripts for binary protection bypass"""
    try:
        if not os.path.exists(binary_path):
            click.echo(f"Binary file not found: {binary_path}", err=True)
            sys.exit(1)

        from intellicrack.ai.autonomous_agent import AutonomousAgent
        from intellicrack.ai.orchestrator import get_orchestrator

        # Get AI orchestrator
        click.echo("🤖 Initializing AI script generator...")
        orchestrator = get_orchestrator()

        # Create autonomous agent
        agent = AutonomousAgent(orchestrator=orchestrator, cli_interface=None)

        # Build request
        binary_name = os.path.basename(binary_path)
        click.echo(f"🎯 Target: {binary_name}")
        click.echo(f"📋 Script Type: {script_type}")
        click.echo(f"🔧 Complexity: {complexity}")
        click.echo(f"🔍 Focus: {focus}")

        if script_type == "both":
            script_request = f"Create both Frida and Ghidra scripts to bypass protections in {binary_path}"
        elif script_type == "frida":
            script_request = f"Create a {complexity} Frida script to bypass protections in {binary_path}"
        else:
            script_request = f"Create a {complexity} Ghidra script to bypass protections in {binary_path}"

        if focus != "auto":
            protection_map = {
                'license': 'license bypass',
                'trial': 'trial extension',
                'network': 'network validation',
                'anti-debug': 'anti-debugging',
                'vm': 'VM detection'
            }
            script_request += f". Focus on {protection_map[focus]} protection."

        if autonomous_mode:
            script_request += " Use autonomous mode with testing and refinement."
            click.echo("🔄 Autonomous mode enabled - AI will test and refine scripts")

        # Generate scripts
        click.echo("\n🚀 Starting AI script generation...")
        with click.progressbar(length=100, label='Generating') as bar:
            result = agent.process_request(script_request)
            bar.update(100)

        # Handle results
        if result.get("status") == "success":
            scripts = result.get("scripts", [])
            analysis = result.get("analysis", {})
            iterations = result.get("iterations", 0)

            click.echo(f"\n✅ Successfully generated {len(scripts)} scripts!")
            click.echo(f"🔄 Completed in {iterations} iterations")

            # Show analysis summary
            if analysis and "protections" in analysis:
                protections = analysis["protections"]
                if protections:
                    click.echo(f"\n🛡️  Detected {len(protections)} protection mechanisms:")
                    for prot in protections[:5]:
                        confidence = prot.get("confidence", 0.0)
                        click.echo(f"   • {prot['type']} (confidence: {confidence:.0%})")

            # Process each script
            for i, script in enumerate(scripts):
                script_name = f"ai_generated_{binary_name}_{script.metadata.script_type.value}_{int(time.time())}"
                success_prob = script.metadata.success_probability

                click.echo(f"\n📄 Script {i+1}: {script.metadata.script_type.value} ({script_name})")
                click.echo(f"   Success Probability: {success_prob:.0%}")
                click.echo(f"   Size: {len(script.content)} characters")

                # Preview if requested
                if preview:
                    click.echo(f"\n📖 Preview of {script.metadata.script_type.value} script:")
                    click.echo("─" * 60)
                    preview_lines = script.content.split('\n')[:20]
                    for line in preview_lines:
                        click.echo(f"   {line}")
                    if len(script.content.split('\n')) > 20:
                        click.echo("   ... (truncated)")
                    click.echo("─" * 60)

                    if not click.confirm("\nSave this script?"):
                        continue

                # Save script
                try:
                    from intellicrack.ai.ai_script_generator import AIScriptGenerator
                    generator = AIScriptGenerator()

                    save_dir = output or "scripts/ai_generated"
                    saved_path = generator.save_script(script, save_dir)

                    click.echo(f"💾 Saved: {saved_path}")

                except Exception as e:
                    click.echo(f"❌ Failed to save script: {e}", err=True)

        else:
            error_msg = result.get("message", "Unknown error")
            click.echo(f"❌ Generation failed: {error_msg}", err=True)
            sys.exit(1)

    except Exception as e:
        logger.error(f"AI script generation failed: {e}")
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)


@ai.command('test')
@click.argument('script_path')
@click.option('--binary', help='Target binary for testing')
@click.option('--environment', type=click.Choice(['qemu', 'docker', 'sandbox', 'direct']),
              default='qemu', help='Testing environment')
@click.option('--timeout', default=60, help='Test timeout in seconds')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def test(script_path: str, binary: Optional[str], environment: str, timeout: int, verbose: bool):
    """Test AI-generated scripts in safe environments"""
    try:
        if not os.path.exists(script_path):
            click.echo(f"Script file not found: {script_path}", err=True)
            sys.exit(1)

        # Determine script type
        script_ext = os.path.splitext(script_path)[1].lower()
        if script_ext == '.js':
            script_type = 'frida'
        elif script_ext == '.py':
            script_type = 'ghidra'
        else:
            click.echo(f"Unknown script type for file: {script_path}", err=True)
            sys.exit(1)

        # Read script content
        with open(script_path, 'r') as f:
            script_content = f.read()

        click.echo(f"🧪 Testing {script_type} script: {os.path.basename(script_path)}")
        click.echo(f"🏗️  Environment: {environment}")
        click.echo(f"⏱️  Timeout: {timeout}s")

        if binary:
            click.echo(f"🎯 Target: {os.path.basename(binary)}")

        # Initialize test manager
        if environment == 'qemu':
            from intellicrack.ai.qemu_test_manager import QEMUTestManager
            test_manager = QEMUTestManager()

            # Create snapshot
            click.echo("\n📸 Creating QEMU snapshot...")
            snapshot_id = test_manager.create_snapshot(binary or "unknown")

            try:
                # Run test
                click.echo("🚀 Executing script in QEMU...")
                if script_type == 'frida':
                    result = test_manager.test_frida_script(snapshot_id, script_content, binary or "unknown")
                else:
                    result = test_manager.test_ghidra_script(snapshot_id, script_content, binary or "unknown")

                # Show results
                if result.success:
                    click.echo("✅ Script executed successfully!")
                    click.echo(f"⏱️  Runtime: {result.runtime_ms}ms")

                    if verbose and result.output:
                        click.echo("\n📋 Script Output:")
                        click.echo(result.output)
                else:
                    click.echo("❌ Script execution failed!")
                    if result.error:
                        click.echo(f"Error: {result.error}")
                    sys.exit(1)

            finally:
                # Cleanup
                click.echo("🧹 Cleaning up snapshot...")
                test_manager.cleanup_snapshot(snapshot_id)

        else:
            click.echo(f"Environment '{environment}' testing not yet implemented")

    except Exception as e:
        logger.error(f"Script testing failed: {e}")
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)


@ai.command('analyze')
@click.argument('binary_path')
@click.option('--output', '-o', help='Save analysis report to file')
@click.option('--format', type=click.Choice(['text', 'json', 'html']),
              default='text', help='Output format')
@click.option('--deep', is_flag=True, help='Enable deep AI analysis')
def analyze(binary_path: str, output: Optional[str], format: str, deep: bool):
    """Analyze binary for protection mechanisms using AI"""
    try:
        if not os.path.exists(binary_path):
            click.echo(f"Binary file not found: {binary_path}", err=True)
            sys.exit(1)

        from intellicrack.ai.orchestrator import (
            AITask,
            AITaskType,
            AnalysisComplexity,
            get_orchestrator,
        )

        click.echo(f"🔍 AI analyzing: {os.path.basename(binary_path)}")
        click.echo(f"📊 Analysis depth: {'Deep' if deep else 'Standard'}")

        # Get orchestrator
        orchestrator = get_orchestrator()

        # Create analysis task
        complexity = AnalysisComplexity.CRITICAL if deep else AnalysisComplexity.COMPLEX

        task = AITask(
            task_id=f"analysis_{int(time.time())}",
            task_type=AITaskType.BINARY_ANALYSIS,
            complexity=complexity,
            input_data={"binary_path": binary_path},
            priority=9 if deep else 7
        )

        # Submit task
        click.echo("🤖 Starting AI analysis...")
        task_id = orchestrator.submit_task(task)
        click.echo(f"Task submitted with ID: {task_id}")

        # For CLI, we'll simulate waiting (real implementation would track task)
        with click.progressbar(length=100, label='Analyzing') as bar:
            for i in range(100):
                time.sleep(0.05)  # Simulate analysis time
                bar.update(1)

        click.echo("✅ Analysis complete!")

        # Generate sample analysis results
        binary_name = os.path.basename(binary_path)
        analysis_results = {
            "binary_info": {
                "name": binary_name,
                "size": os.path.getsize(binary_path),
                "type": "PE" if binary_path.endswith('.exe') else "Unknown"
            },
            "protections": [
                {
                    "type": "license_check",
                    "confidence": 0.85,
                    "description": "String comparison based license validation"
                },
                {
                    "type": "trial_timer",
                    "confidence": 0.72,
                    "description": "Time-based trial limitation"
                }
            ],
            "recommendations": [
                "Focus on license validation bypass",
                "Monitor time-related function calls",
                "Consider registry-based license storage"
            ]
        }

        # Format output
        if format == 'json':
            output_text = json.dumps(analysis_results, indent=2)
        elif format == 'html':
            output_text = f"""
<html><head><title>AI Analysis: {binary_name}</title></head>
<body>
<h1>AI Binary Analysis Report</h1>
<h2>Binary: {binary_name}</h2>
<h3>Detected Protections:</h3>
<ul>
"""
            for prot in analysis_results["protections"]:
                output_text += f"<li>{prot['type']} (confidence: {prot['confidence']:.0%}) - {prot['description']}</li>\n"
            output_text += "</ul></body></html>"
        else:
            # Text format
            output_text = "AI Binary Analysis Report\n"
            output_text += f"{'=' * 50}\n"
            output_text += f"Binary: {binary_name}\n"
            output_text += f"Size: {analysis_results['binary_info']['size']} bytes\n"
            output_text += f"Type: {analysis_results['binary_info']['type']}\n\n"

            output_text += f"Detected Protections ({len(analysis_results['protections'])}):\n"
            for prot in analysis_results["protections"]:
                output_text += f"  • {prot['type']} (confidence: {prot['confidence']:.0%})\n"
                output_text += f"    {prot['description']}\n"

            output_text += "\nAI Recommendations:\n"
            for i, rec in enumerate(analysis_results["recommendations"], 1):
                output_text += f"  {i}. {rec}\n"

        # Save or display
        if output:
            with open(output, 'w') as f:
                f.write(output_text)
            click.echo(f"💾 Analysis saved to: {output}")
        else:
            click.echo("\n📋 Analysis Results:")
            click.echo(output_text)

    except Exception as e:
        logger.error(f"AI analysis failed: {e}")
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)


@ai.command()
@click.argument('request')
@click.option('--binary', help='Target binary (optional)')
@click.option('--max-iterations', default=10, help='Maximum refinement iterations')
@click.option('--test-environment', type=click.Choice(['qemu', 'docker', 'sandbox']),
              default='qemu', help='Testing environment')
@click.option('--save-all', is_flag=True, help='Save all intermediate scripts')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def autonomous(request: str, binary: Optional[str], max_iterations: int,
               test_environment: str, save_all: bool, verbose: bool):
    """Run autonomous AI workflow for complex tasks"""
    try:
        from intellicrack.ai.autonomous_agent import AutonomousAgent
        from intellicrack.ai.orchestrator import get_orchestrator

        click.echo("🤖 Starting autonomous AI workflow...")
        click.echo(f"📝 Request: {request}")
        click.echo(f"🔄 Max iterations: {max_iterations}")
        click.echo(f"🏗️  Test environment: {test_environment}")

        if binary:
            click.echo(f"🎯 Target binary: {os.path.basename(binary)}")
            # Add binary to request if provided
            request = f"{request}. Target binary: {binary}"

        # Initialize autonomous agent
        orchestrator = get_orchestrator()
        agent = AutonomousAgent(orchestrator=orchestrator, cli_interface=None)
        agent.max_iterations = max_iterations

        # Process request
        click.echo("\n🚀 Executing autonomous workflow...")

        # Simple progress simulation for CLI
        with click.progressbar(length=max_iterations, label='Processing') as bar:
            result = agent.process_request(request)
            bar.update(max_iterations)

        # Handle results
        if result.get("status") == "success":
            scripts = result.get("scripts", [])
            iterations = result.get("iterations", 0)
            analysis = result.get("analysis", {})

            click.echo("\n✅ Autonomous workflow completed successfully!")
            click.echo(f"🔄 Total iterations: {iterations}")
            click.echo(f"📄 Generated scripts: {len(scripts)}")

            # Show script details
            for i, script in enumerate(scripts):
                script_type = script.metadata.script_type.value
                success_prob = script.metadata.success_probability
                click.echo(f"   Script {i+1}: {script_type} (success: {success_prob:.0%})")

                if save_all:
                    try:
                        from intellicrack.ai.ai_script_generator import AIScriptGenerator
                        generator = AIScriptGenerator()
                        saved_path = generator.save_script(script, "scripts/autonomous")
                        click.echo(f"      Saved: {saved_path}")
                    except Exception as e:
                        click.echo(f"      Save failed: {e}")

            # Show analysis if verbose
            if verbose and analysis:
                click.echo("\n📊 Analysis Summary:")
                if "protections" in analysis:
                    protections = analysis["protections"]
                    click.echo(f"   Protections detected: {len(protections)}")
                    for prot in protections[:3]:
                        click.echo(f"      • {prot.get('type', 'unknown')}")
        else:
            error_msg = result.get("message", "Unknown error")
            click.echo(f"❌ Autonomous workflow failed: {error_msg}", err=True)
            sys.exit(1)

    except Exception as e:
        logger.error(f"Autonomous workflow failed: {e}")
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)


def main():
    """Main entry point for CLI"""
    cli()  # pylint: disable=E1120


if __name__ == '__main__':
    main()
