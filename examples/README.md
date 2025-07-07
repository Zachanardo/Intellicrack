# Intellicrack Examples

This directory contains practical examples and tutorials demonstrating how to use Intellicrack's features and APIs.

## Available Examples

### Basic Usage Examples

#### `background_loading_example.py`
Demonstrates how to perform background loading and analysis operations without blocking the UI.

```python
# Example of background analysis
from intellicrack.ai.lazy_model_loader import LazyModelLoader
from intellicrack.core.analysis import CoreAnalyzer

# Load models in background
loader = LazyModelLoader()
loader.load_models_async()

# Perform analysis while models load
analyzer = CoreAnalyzer()
result = analyzer.quick_analysis("target.exe")
```

**Features Demonstrated:**
- Asynchronous model loading
- Non-blocking analysis operations
- Progress tracking and callbacks
- Resource management

**Usage:**
```bash
python examples/background_loading_example.py target.exe
```

## Example Categories

### 1. Basic Analysis Examples
- **Binary Information Extraction** - Get file metadata, hashes, and basic properties
- **Protection Detection** - Identify packers, obfuscation, and anti-analysis techniques
- **String Extraction** - Extract and analyze strings from binaries
- **Import/Export Analysis** - Analyze API usage and dependencies

### 2. Advanced Analysis Examples
- **Symbolic Execution** - Path exploration and constraint solving
- **Taint Analysis** - Data flow tracking and vulnerability identification
- **Control Flow Analysis** - CFG generation and analysis
- **Vulnerability Detection** - Automated vulnerability scanning

### 3. AI Integration Examples
- **Script Generation** - AI-powered Frida script generation
- **Pattern Recognition** - ML-based pattern detection
- **Behavioral Analysis** - AI-driven behavior classification
- **Threat Intelligence** - Automated threat analysis

### 4. Dynamic Analysis Examples
- **Frida Instrumentation** - Runtime instrumentation and hooking
- **API Monitoring** - System call and API monitoring
- **Memory Analysis** - Runtime memory inspection
- **Network Monitoring** - Network traffic analysis

### 5. Exploitation Examples
- **Payload Generation** - Creating custom payloads
- **ROP Chain Generation** - Return-oriented programming
- **Shellcode Development** - Custom shellcode creation
- **Bypass Techniques** - Modern mitigation bypasses

### 6. Integration Examples
- **Plugin Development** - Creating custom plugins
- **API Integration** - Using Intellicrack's APIs
- **Workflow Automation** - Automated analysis workflows
- **Reporting** - Custom report generation

## Quick Start Examples

### Example 1: Basic Binary Analysis
```python
#!/usr/bin/env python3
"""
Basic binary analysis example
"""

from intellicrack.core.analysis import CoreAnalyzer
from intellicrack.utils.binary_analysis import get_file_info
import sys

def analyze_binary(binary_path):
    """Perform basic binary analysis"""
    # Get file information
    file_info = get_file_info(binary_path)
    print(f"File: {file_info['name']}")
    print(f"Size: {file_info['size']} bytes")
    print(f"Type: {file_info['type']}")
    
    # Perform analysis
    analyzer = CoreAnalyzer()
    results = analyzer.analyze_binary(binary_path)
    
    # Display results
    print(f"\nAnalysis Results:")
    print(f"Architecture: {results.get('architecture', 'Unknown')}")
    print(f"Entry Point: {results.get('entry_point', 'Unknown')}")
    print(f"Sections: {len(results.get('sections', []))}")
    
    # Check for protections
    protections = results.get('protections', [])
    if protections:
        print(f"\nProtections Detected:")
        for protection in protections:
            print(f"  - {protection}")
    else:
        print("\nNo protections detected")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python basic_analysis.py <binary_path>")
        sys.exit(1)
    
    analyze_binary(sys.argv[1])
```

### Example 2: AI-Powered Script Generation
```python
#!/usr/bin/env python3
"""
AI script generation example
"""

from intellicrack.ai.ai_script_generator import AIScriptGenerator
from intellicrack.core.frida_manager import FridaManager
import sys

def generate_and_run_script(binary_path, target_type="license_bypass"):
    """Generate AI script and execute it"""
    # Initialize AI generator
    generator = AIScriptGenerator()
    
    # Generate Frida script
    print(f"Generating {target_type} script for {binary_path}...")
    script = generator.generate_frida_script(
        binary_path=binary_path,
        analysis_type=target_type,
        complexity_level="intermediate"
    )
    
    if script:
        print("Script generated successfully!")
        print(f"Script preview (first 500 chars):")
        print(script[:500] + "..." if len(script) > 500 else script)
        
        # Execute script
        manager = FridaManager()
        result = manager.execute_script(script, binary_path)
        
        if result['success']:
            print("Script executed successfully!")
            print(f"Results: {result.get('output', 'No output')}")
        else:
            print(f"Script execution failed: {result.get('error', 'Unknown error')}")
    else:
        print("Failed to generate script")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python ai_script_generation.py <binary_path> [target_type]")
        print("Target types: license_bypass, api_hooking, crypto_analysis")
        sys.exit(1)
    
    binary_path = sys.argv[1]
    target_type = sys.argv[2] if len(sys.argv) > 2 else "license_bypass"
    
    generate_and_run_script(binary_path, target_type)
```

### Example 3: Vulnerability Scanning
```python
#!/usr/bin/env python3
"""
Vulnerability scanning example
"""

from intellicrack.core.vulnerability_research import VulnerabilityAnalyzer
from intellicrack.core.analysis.vulnerability_engine import VulnerabilityEngine
import sys

def scan_for_vulnerabilities(binary_path):
    """Scan binary for vulnerabilities"""
    # Initialize vulnerability analyzer
    analyzer = VulnerabilityAnalyzer()
    
    print(f"Scanning {binary_path} for vulnerabilities...")
    
    # Perform vulnerability scan
    vulnerabilities = analyzer.scan_binary(binary_path)
    
    if vulnerabilities:
        print(f"\nFound {len(vulnerabilities)} potential vulnerabilities:")
        
        for i, vuln in enumerate(vulnerabilities, 1):
            print(f"\n{i}. {vuln.type.upper()}")
            print(f"   Severity: {vuln.severity}")
            print(f"   Location: {vuln.location}")
            print(f"   Description: {vuln.description}")
            
            if hasattr(vuln, 'recommendation'):
                print(f"   Recommendation: {vuln.recommendation}")
    else:
        print("No vulnerabilities detected")
    
    # Generate detailed report
    report = analyzer.generate_report(vulnerabilities)
    with open(f"{binary_path}_vulnerability_report.json", "w") as f:
        import json
        json.dump(report, f, indent=2)
    
    print(f"\nDetailed report saved to: {binary_path}_vulnerability_report.json")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python vulnerability_scan.py <binary_path>")
        sys.exit(1)
    
    scan_for_vulnerabilities(sys.argv[1])
```

### Example 4: Network Traffic Analysis
```python
#!/usr/bin/env python3
"""
Network traffic analysis example
"""

from intellicrack.core.network.traffic_analyzer import NetworkTrafficAnalyzer
from intellicrack.core.network.ssl_interceptor import SSLInterceptor
import time
import sys

def analyze_network_traffic(duration=60):
    """Analyze network traffic for specified duration"""
    # Initialize analyzers
    traffic_analyzer = NetworkTrafficAnalyzer()
    ssl_interceptor = SSLInterceptor()
    
    print(f"Starting network analysis for {duration} seconds...")
    
    # Start traffic capture
    traffic_analyzer.start_capture()
    ssl_interceptor.start_interception()
    
    try:
        # Monitor for specified duration
        time.sleep(duration)
    except KeyboardInterrupt:
        print("\nStopping analysis...")
    
    # Stop capture and analyze
    packets = traffic_analyzer.stop_capture()
    ssl_data = ssl_interceptor.stop_interception()
    
    # Analyze captured data
    analysis = traffic_analyzer.analyze_packets(packets)
    
    print(f"\nAnalysis Results:")
    print(f"Total packets captured: {len(packets)}")
    print(f"Protocols detected: {', '.join(analysis.get('protocols', []))}")
    print(f"Unique hosts: {len(analysis.get('hosts', []))}")
    
    # SSL/TLS analysis
    if ssl_data:
        print(f"SSL/TLS connections: {len(ssl_data)}")
        for conn in ssl_data[:5]:  # Show first 5
            print(f"  - {conn['host']}:{conn['port']} (TLS {conn.get('version', 'unknown')})")
    
    # Export results
    traffic_analyzer.export_results("network_analysis.json")
    print(f"\nResults exported to: network_analysis.json")

if __name__ == "__main__":
    duration = int(sys.argv[1]) if len(sys.argv) > 1 else 60
    analyze_network_traffic(duration)
```

## Plugin Development Examples

### Example Plugin Template
```python
#!/usr/bin/env python3
"""
Example plugin template
"""

from intellicrack.plugins import PluginBase
import os

class ExamplePlugin(PluginBase):
    def __init__(self):
        super().__init__()
        self.name = "Example Plugin"
        self.version = "1.0.0"
        self.description = "Example plugin demonstrating basic functionality"
        self.author = "Intellicrack Team"
    
    def validate_input(self, binary_path):
        """Validate plugin input"""
        if not os.path.exists(binary_path):
            return False, "File does not exist"
        
        if not os.path.isfile(binary_path):
            return False, "Path is not a file"
        
        return True, "Valid input"
    
    def run(self, binary_path, **kwargs):
        """Main plugin execution"""
        try:
            # Validate input
            valid, message = self.validate_input(binary_path)
            if not valid:
                return {
                    'success': False,
                    'error': message
                }
            
            # Plugin logic here
            results = self.analyze_binary(binary_path)
            
            return {
                'success': True,
                'results': results,
                'plugin_info': {
                    'name': self.name,
                    'version': self.version
                }
            }
        
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def analyze_binary(self, binary_path):
        """Perform custom analysis"""
        # Example analysis
        file_size = os.path.getsize(binary_path)
        
        return {
            'file_path': binary_path,
            'file_size': file_size,
            'analysis_type': 'basic_info'
        }
    
    def get_config_schema(self):
        """Return configuration schema"""
        return {
            'timeout': {
                'type': 'int',
                'default': 300,
                'description': 'Analysis timeout in seconds'
            },
            'deep_analysis': {
                'type': 'bool',
                'default': False,
                'description': 'Enable deep analysis'
            }
        }

# Plugin registration
def create_plugin():
    return ExamplePlugin()
```

## API Integration Examples

### REST API Usage
```python
#!/usr/bin/env python3
"""
REST API integration example
"""

import requests
import json

class IntellicracAPI:
    def __init__(self, base_url="http://localhost:8080"):
        self.base_url = base_url
    
    def analyze_binary(self, binary_path):
        """Submit binary for analysis via API"""
        with open(binary_path, 'rb') as f:
            files = {'binary': f}
            response = requests.post(
                f"{self.base_url}/api/analyze",
                files=files
            )
        
        return response.json()
    
    def get_analysis_status(self, analysis_id):
        """Check analysis status"""
        response = requests.get(
            f"{self.base_url}/api/analysis/{analysis_id}/status"
        )
        return response.json()
    
    def get_analysis_results(self, analysis_id):
        """Get analysis results"""
        response = requests.get(
            f"{self.base_url}/api/analysis/{analysis_id}/results"
        )
        return response.json()

# Usage example
if __name__ == "__main__":
    api = IntellicracAPI()
    
    # Submit analysis
    result = api.analyze_binary("sample.exe")
    analysis_id = result['analysis_id']
    
    print(f"Analysis submitted with ID: {analysis_id}")
    
    # Wait for completion
    import time
    while True:
        status = api.get_analysis_status(analysis_id)
        if status['status'] == 'completed':
            break
        elif status['status'] == 'failed':
            print("Analysis failed")
            exit(1)
        
        time.sleep(5)
    
    # Get results
    results = api.get_analysis_results(analysis_id)
    print(json.dumps(results, indent=2))
```

## Workflow Automation Examples

### Batch Analysis Script
```python
#!/usr/bin/env python3
"""
Batch analysis automation example
"""

import os
import json
from pathlib import Path
from intellicrack.core.analysis import CoreAnalyzer
from intellicrack.core.vulnerability_research import VulnerabilityAnalyzer

def batch_analyze_directory(directory_path, output_dir="results"):
    """Analyze all binaries in a directory"""
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    
    # Initialize analyzers
    core_analyzer = CoreAnalyzer()
    vuln_analyzer = VulnerabilityAnalyzer()
    
    # Find binary files
    binary_extensions = ['.exe', '.dll', '.so', '.dylib']
    binary_files = []
    
    for ext in binary_extensions:
        binary_files.extend(Path(directory_path).glob(f"**/*{ext}"))
    
    print(f"Found {len(binary_files)} binary files to analyze")
    
    results = []
    
    for i, binary_path in enumerate(binary_files, 1):
        print(f"Analyzing {i}/{len(binary_files)}: {binary_path.name}")
        
        try:
            # Core analysis
            core_results = core_analyzer.analyze_binary(str(binary_path))
            
            # Vulnerability analysis
            vulnerabilities = vuln_analyzer.scan_binary(str(binary_path))
            
            # Combine results
            analysis_result = {
                'file_path': str(binary_path),
                'file_name': binary_path.name,
                'core_analysis': core_results,
                'vulnerabilities': [
                    {
                        'type': v.type,
                        'severity': v.severity,
                        'description': v.description
                    } for v in vulnerabilities
                ],
                'analysis_timestamp': time.time()
            }
            
            results.append(analysis_result)
            
            # Save individual result
            result_file = os.path.join(output_dir, f"{binary_path.stem}_analysis.json")
            with open(result_file, 'w') as f:
                json.dump(analysis_result, f, indent=2)
        
        except Exception as e:
            print(f"Error analyzing {binary_path}: {e}")
            continue
    
    # Save combined results
    combined_file = os.path.join(output_dir, "batch_analysis_results.json")
    with open(combined_file, 'w') as f:
        json.dump({
            'total_files': len(binary_files),
            'successful_analyses': len(results),
            'results': results
        }, f, indent=2)
    
    print(f"Batch analysis completed. Results saved to {output_dir}")

if __name__ == "__main__":
    import sys
    import time
    
    if len(sys.argv) != 2:
        print("Usage: python batch_analysis.py <directory_path>")
        sys.exit(1)
    
    batch_analyze_directory(sys.argv[1])
```

## Getting Started

### Prerequisites
- Intellicrack installed and configured
- Python 3.11 or 3.12
- Required dependencies (see `requirements/requirements.txt`)

### Running Examples
1. Navigate to the examples directory:
   ```bash
   cd examples/
   ```

2. Run an example:
   ```bash
   python background_loading_example.py /path/to/binary.exe
   ```

3. View the results and modify the examples for your use case

### Creating Custom Examples
1. Copy an existing example as a template
2. Modify the analysis logic for your needs
3. Add appropriate error handling
4. Document your example
5. Test with various binary types

## Example Data

### Test Binaries
For testing examples, you can use:
- System binaries (like `notepad.exe`, `calc.exe`)
- Open source compiled programs
- Your own test applications

### Sample Configurations
```json
{
    "analysis": {
        "timeout": 300,
        "parallel_threads": 4,
        "enable_ai": true
    },
    "logging": {
        "level": "INFO",
        "file_output": true
    },
    "plugins": {
        "enabled": ["basic_analysis", "vulnerability_scan"],
        "disabled": ["experimental_features"]
    }
}
```

## Best Practices

### Error Handling
```python
try:
    result = analyzer.analyze_binary(binary_path)
except FileNotFoundError:
    print(f"Binary not found: {binary_path}")
except PermissionError:
    print(f"Permission denied: {binary_path}")
except Exception as e:
    print(f"Analysis failed: {e}")
```

### Resource Management
```python
# Use context managers for resources
with analyzer.create_session() as session:
    result = session.analyze(binary_path)
    # Session automatically cleaned up
```

### Configuration
```python
# Load configuration
from intellicrack.utils.config import load_config
config = load_config("analysis_config.json")

# Use configuration
analyzer = CoreAnalyzer(config=config)
```

## Contributing Examples

To contribute new examples:
1. Follow the existing code style
2. Include comprehensive error handling
3. Add clear documentation and comments
4. Test with multiple binary types
5. Update this README with your example

### Example Template
```python
#!/usr/bin/env python3
"""
[Example Name] - [Brief Description]

This example demonstrates [specific functionality].

Usage:
    python example_name.py <arguments>

Requirements:
    - [list requirements]

Author: [Your Name]
"""

# Imports
import sys
from intellicrack.core.analysis import CoreAnalyzer

def main():
    """Main example function"""
    # Implementation here
    pass

if __name__ == "__main__":
    main()
```

## Additional Resources

- [API Documentation](../docs/api_reference.md)
- [Plugin Development Guide](../docs/development/plugins.md)
- [Configuration Guide](../docs/usage/basic_analysis.md)
- [Contributing Guidelines](../CONTRIBUTING.md)

For questions or support, please refer to the main project documentation or create an issue on the project repository.