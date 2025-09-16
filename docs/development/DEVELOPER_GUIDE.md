# Developer Guide

## Overview

This guide provides comprehensive information for developers working with, extending, or contributing to the Intellicrack platform. It covers the development environment, architecture patterns, API integration, plugin development, and contribution guidelines.

## Table of Contents

1. [Development Environment Setup](#development-environment-setup)
2. [Architecture and Design Patterns](#architecture-and-design-patterns)
3. [Plugin Development](#plugin-development)
4. [API Integration](#api-integration)
5. [VM Framework and Binary Emulation](#vm-framework-and-binary-emulation)
6. [Testing Framework](#testing-framework)
7. [Code Quality and Standards](#code-quality-and-standards)
8. [Contribution Guidelines](#contribution-guidelines)
9. [Performance Optimization](#performance-optimization)
10. [Security Development Practices](#security-development-practices)
11. [Deployment and Distribution](#deployment-and-distribution)

## Development Environment Setup

### Prerequisites

**System Requirements:**
- Python 3.12+ (required)
- Git 2.40+
- Node.js 18+ (for Frida script development)
- Visual Studio Code or PyCharm (recommended IDEs)

**Development Tools:**
```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Install pre-commit hooks
pre-commit install

# Install external development tools
./setup/install_dev_tools.sh
```

### Project Structure

```
intellicrack/
├── intellicrack/              # Main package
│   ├── ai/                    # AI and ML modules
│   ├── core/                  # Core analysis engines
│   ├── ui/                    # User interface components
│   ├── utils/                 # Utility modules
│   ├── plugins/               # Plugin system
│   └── main.py               # Application entry point
├── docs/                      # Documentation
│   ├── api/                   # API documentation
│   ├── guides/                # User guides
│   ├── development/           # Developer documentation
│   └── security/              # Security guidelines
├── tests/                     # Test suite
│   ├── unit/                  # Unit tests
│   ├── integration/           # Integration tests
│   └── performance/           # Performance tests

├── requirements/              # Dependencies
└── setup/                     # Setup and installation
```

### Development Workflow

#### 1. Environment Setup
```bash
# Clone repository
git clone https://github.com/your-org/intellicrack.git
cd intellicrack

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements/requirements-dev.txt

# Configure development environment
cp config/config.dev.yaml config/config.yaml
```

#### 2. Code Style Setup
```bash
# Install code formatting tools
pip install black isort flake8 mypy

# Configure IDE settings
cp .vscode/settings.example.json .vscode/settings.json

# Run code formatting
black intellicrack/
isort intellicrack/
```

#### 3. Testing Setup
```bash
# Run unit tests
pytest tests/unit/

# Run integration tests
pytest tests/integration/

# Run with coverage
pytest --cov=intellicrack --cov-report=html tests/
```

## Architecture and Design Patterns

### Core Architectural Patterns

#### 1. Modular Architecture
The platform follows a modular architecture with clear separation of concerns:

```python
# Example module structure
class AnalysisModule(ABC):
    """Base class for all analysis modules."""

    @abstractmethod
    def analyze(self, target: str, options: Dict[str, Any]) -> AnalysisResult:
        """Perform analysis on target."""
        pass

    @abstractmethod
    def get_capabilities(self) -> List[str]:
        """Get module capabilities."""
        pass

    @abstractmethod
    def validate_target(self, target: str) -> bool:
        """Validate if target is supported."""
        pass

class BinaryAnalyzer(AnalysisModule):
    """Binary analysis implementation."""

    def analyze(self, target: str, options: Dict[str, Any]) -> AnalysisResult:
        # Implementation details
        pass
```

#### 2. Plugin Architecture
```python
class PluginManager:
    """Manages plugin loading and execution."""

    def __init__(self):
        self.plugins: Dict[str, Plugin] = {}
        self.plugin_registry = PluginRegistry()

    def load_plugin(self, plugin_path: str) -> bool:
        """Load a plugin from file."""
        try:
            spec = importlib.util.spec_from_file_location("plugin", plugin_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            # Validate plugin interface
            plugin_class = getattr(module, 'Plugin', None)
            if not plugin_class or not issubclass(plugin_class, BasePlugin):
                raise PluginError("Invalid plugin interface")

            # Instantiate and register plugin
            plugin = plugin_class()
            self.plugins[plugin.name] = plugin
            self.plugin_registry.register(plugin)

            return True

        except Exception as e:
            logger.error(f"Failed to load plugin {plugin_path}: {e}")
            return False

    def execute_plugin(self, plugin_name: str, **kwargs) -> PluginResult:
        """Execute a loaded plugin."""
        if plugin_name not in self.plugins:
            raise PluginNotFoundError(f"Plugin {plugin_name} not loaded")

        plugin = self.plugins[plugin_name]
        return plugin.execute(**kwargs)
```

#### 3. Event-Driven Architecture
```python
class EventBus:
    """Central event bus for component communication."""

    def __init__(self):
        self.handlers: Dict[str, List[Callable]] = {}
        self.async_handlers: Dict[str, List[Callable]] = {}

    def subscribe(self, event_type: str, handler: Callable):
        """Subscribe to event type."""
        if event_type not in self.handlers:
            self.handlers[event_type] = []
        self.handlers[event_type].append(handler)

    def publish(self, event: Event):
        """Publish event to subscribers."""
        handlers = self.handlers.get(event.type, [])
        for handler in handlers:
            try:
                handler(event)
            except Exception as e:
                logger.error(f"Event handler error: {e}")

    async def publish_async(self, event: Event):
        """Publish event asynchronously."""
        handlers = self.async_handlers.get(event.type, [])
        tasks = []
        for handler in handlers:
            task = asyncio.create_task(handler(event))
            tasks.append(task)

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

# Usage example
event_bus = EventBus()

# Subscribe to analysis events
event_bus.subscribe("analysis_started", on_analysis_started)
event_bus.subscribe("analysis_completed", on_analysis_completed)

# Publish events
event_bus.publish(AnalysisStartedEvent(target="app.exe"))
```

### Design Patterns

#### 1. Factory Pattern for Analysis Engines
```python
class AnalysisEngineFactory:
    """Factory for creating analysis engines."""

    _engines = {
        "binary": BinaryAnalyzer,
        "dynamic": DynamicAnalyzer,
        "entropy": EntropyAnalyzer,
        "vulnerability": VulnerabilityEngine,
        "network": NetworkAnalyzer
    }

    @classmethod
    def create_engine(cls, engine_type: str, config: Dict[str, Any]) -> AnalysisModule:
        """Create analysis engine of specified type."""
        if engine_type not in cls._engines:
            raise ValueError(f"Unknown engine type: {engine_type}")

        engine_class = cls._engines[engine_type]
        return engine_class(config)

    @classmethod
    def register_engine(cls, engine_type: str, engine_class: Type[AnalysisModule]):
        """Register new engine type."""
        cls._engines[engine_type] = engine_class

    @classmethod
    def get_available_engines(cls) -> List[str]:
        """Get list of available engine types."""
        return list(cls._engines.keys())
```

#### 2. Observer Pattern for Progress Tracking
```python
class ProgressTracker:
    """Observable progress tracker."""

    def __init__(self):
        self.observers: List[ProgressObserver] = []
        self.current_progress = 0
        self.total_steps = 0
        self.current_step = ""

    def add_observer(self, observer: ProgressObserver):
        """Add progress observer."""
        self.observers.append(observer)

    def remove_observer(self, observer: ProgressObserver):
        """Remove progress observer."""
        self.observers.remove(observer)

    def update_progress(self, current: int, total: int, step: str):
        """Update progress and notify observers."""
        self.current_progress = current
        self.total_steps = total
        self.current_step = step

        for observer in self.observers:
            observer.on_progress_updated(current, total, step)

    def complete(self, success: bool, message: str = ""):
        """Mark progress as complete."""
        for observer in self.observers:
            observer.on_completion(success, message)

class ProgressObserver(ABC):
    """Abstract progress observer."""

    @abstractmethod
    def on_progress_updated(self, current: int, total: int, step: str):
        """Handle progress update."""
        pass

    @abstractmethod
    def on_completion(self, success: bool, message: str):
        """Handle completion."""
        pass
```

## Plugin Development

### Plugin Interface

#### 1. Base Plugin Class
```python
class BasePlugin(ABC):
    """Base class for all plugins."""

    def __init__(self):
        self.name = self.__class__.__name__
        self.version = "1.0.0"
        self.description = ""
        self.author = ""
        self.capabilities = []

    @abstractmethod
    def initialize(self, context: PluginContext) -> bool:
        """Initialize plugin with context."""
        pass

    @abstractmethod
    def execute(self, **kwargs) -> PluginResult:
        """Execute plugin functionality."""
        pass

    @abstractmethod
    def cleanup(self):
        """Cleanup plugin resources."""
        pass

    def get_metadata(self) -> PluginMetadata:
        """Get plugin metadata."""
        return PluginMetadata(
            name=self.name,
            version=self.version,
            description=self.description,
            author=self.author,
            capabilities=self.capabilities
        )
```

#### 2. Example Plugin Implementation
```python
class LicenseAnalysisPlugin(BasePlugin):
    """Plugin for license mechanism analysis."""

    def __init__(self):
        super().__init__()
        self.name = "LicenseAnalysisPlugin"
        self.version = "1.2.0"
        self.description = "Analyzes software license protection mechanisms"
        self.author = "Security Research Team"
        self.capabilities = ["license_detection", "validation_analysis", "bypass_assessment"]

        self.patterns = LicensePatternDatabase()
        self.analyzer = LicenseAnalyzer()

    def initialize(self, context: PluginContext) -> bool:
        """Initialize the license analysis plugin."""
        try:
            # Load license patterns
            self.patterns.load_patterns(context.get_data_path("license_patterns.yaml"))

            # Initialize analyzer with context
            self.analyzer.initialize(context.get_config("license_analysis"))

            logger.info(f"Initialized {self.name} v{self.version}")
            return True

        except Exception as e:
            logger.error(f"Failed to initialize {self.name}: {e}")
            return False

    def execute(self, target_binary: str, analysis_level: str = "standard") -> PluginResult:
        """Execute license analysis on target binary."""
        try:
            # Validate input
            if not os.path.exists(target_binary):
                raise PluginError(f"Target binary not found: {target_binary}")

            # Perform analysis
            results = {}

            # Detect license mechanisms
            license_mechanisms = self.analyzer.detect_mechanisms(target_binary)
            results["mechanisms"] = license_mechanisms

            # Analyze validation routines
            validation_analysis = self.analyzer.analyze_validation(target_binary)
            results["validation"] = validation_analysis

            # Assess bypass difficulty (for security assessment)
            if analysis_level == "advanced":
                bypass_assessment = self.analyzer.assess_bypass_difficulty(target_binary)
                results["bypass_assessment"] = bypass_assessment

            return PluginResult(
                success=True,
                results=results,
                metadata={
                    "plugin": self.name,
                    "version": self.version,
                    "analysis_level": analysis_level,
                    "timestamp": datetime.utcnow().isoformat()
                }
            )

        except Exception as e:
            logger.error(f"License analysis failed: {e}")
            return PluginResult(
                success=False,
                error=str(e),
                metadata={"plugin": self.name, "version": self.version}
            )

    def cleanup(self):
        """Cleanup plugin resources."""
        if hasattr(self, 'analyzer'):
            self.analyzer.cleanup()
```

#### 3. Plugin Configuration
```yaml
# plugin_config.yaml
license_analysis:
  name: "LicenseAnalysisPlugin"
  enabled: true
  config:
    detection_sensitivity: "high"
    analysis_depth: "comprehensive"
    reporting_level: "detailed"
    patterns_update_interval: "daily"

  permissions:
    - "file_read"
    - "network_access"
    - "temporary_file_creation"

  resources:
    max_memory: "512MB"
    max_cpu_time: "300s"
    max_disk_usage: "100MB"
```

### Frida Script Plugins

#### 1. Frida Script Template
```javascript
// frida_license_analysis.js
class LicenseAnalysisScript {
    constructor() {
        this.name = "License Analysis Script";
        this.version = "1.0.0";
        this.hooks = new Map();
        this.results = {};
    }

    initialize() {
        console.log(`[+] Initializing ${this.name} v${this.version}`);

        // Initialize hooks
        this.setupLicenseHooks();
        this.setupRegistryHooks();
        this.setupNetworkHooks();

        console.log("[+] License analysis hooks installed");
    }

    setupLicenseHooks() {
        // Hook common license validation functions
        const licenseAPIs = [
            "CheckLicense",
            "ValidateLicense",
            "VerifyActivation",
            "GetLicenseStatus"
        ];

        licenseAPIs.forEach(api => {
            this.hookAPI(api, (args, retval) => {
                this.results[api] = {
                    called: true,
                    arguments: args,
                    return_value: retval,
                    timestamp: Date.now()
                };
            });
        });
    }

    setupRegistryHooks() {
        // Hook registry access for license storage
        const regAPIs = ["RegOpenKeyExA", "RegQueryValueExA", "RegSetValueExA"];

        regAPIs.forEach(api => {
            this.hookWindowsAPI("advapi32.dll", api, {
                onEnter(args) {
                    const keyName = args[1].readAnsiString();
                    if (keyName && keyName.toLowerCase().includes("license")) {
                        console.log(`[+] License registry access: ${api} - ${keyName}`);
                    }
                }
            });
        });
    }

    setupNetworkHooks() {
        // Hook network functions for online validation
        this.hookWindowsAPI("ws2_32.dll", "connect", {
            onEnter(args) {
                const sockaddr = args[1];
                const family = sockaddr.readU16();

                if (family === 2) { // AF_INET
                    const port = (sockaddr.add(2).readU16() << 8) | (sockaddr.add(2).readU16() >> 8);
                    const ip = sockaddr.add(4).readU32();
                    const ipStr = `${ip & 0xFF}.${(ip >> 8) & 0xFF}.${(ip >> 16) & 0xFF}.${ip >> 24}`;

                    console.log(`[+] Network connection: ${ipStr}:${port}`);

                    // Common license server ports
                    if ([27000, 27001, 7788, 1947].includes(port)) {
                        console.log("[!] Possible license server connection");
                    }
                }
            }
        });
    }

    hookAPI(apiName, callback) {
        // Generic API hooking
        try {
            const modules = Process.enumerateModules();

            for (const module of modules) {
                try {
                    const exports = module.enumerateExports();
                    const targetExport = exports.find(exp => exp.name === apiName);

                    if (targetExport) {
                        Interceptor.attach(targetExport.address, {
                            onEnter(args) {
                                this.args = args;
                            },
                            onLeave(retval) {
                                callback(this.args, retval);
                            }
                        });

                        console.log(`[+] Hooked ${apiName} at ${targetExport.address}`);
                        return true;
                    }
                } catch (e) {
                    // Continue to next module
                }
            }
        } catch (e) {
            console.log(`[-] Failed to hook ${apiName}: ${e.message}`);
        }

        return false;
    }

    hookWindowsAPI(moduleName, apiName, callbacks) {
        try {
            const module = Process.getModuleByName(moduleName);
            const api = module.getExportByName(apiName);

            Interceptor.attach(api, callbacks);
            console.log(`[+] Hooked ${moduleName}!${apiName}`);
        } catch (e) {
            console.log(`[-] Failed to hook ${moduleName}!${apiName}: ${e.message}`);
        }
    }

    getResults() {
        return {
            script_name: this.name,
            version: this.version,
            analysis_results: this.results,
            timestamp: Date.now()
        };
    }
}

// Main execution
Java.perform(() => {
    const script = new LicenseAnalysisScript();
    script.initialize();

    // Export results function for external access
    global.getLicenseAnalysisResults = () => script.getResults();
});
```

### Ghidra Script Plugins

#### 1. Ghidra Script Template
```java
// LicensePatternScanner.java
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;

public class LicensePatternScanner extends GhidraScript {

    @Override
    public void run() throws Exception {
        println("License Pattern Scanner v1.0.0");
        println("Analyzing program for license protection patterns...\n");

        // Scan for license-related functions
        scanLicenseFunctions();

        // Scan for license-related strings
        scanLicenseStrings();

        // Scan for cryptographic patterns
        scanCryptoPatterns();

        // Generate report
        generateReport();
    }

    private void scanLicenseFunctions() throws Exception {
        println("=== License Function Analysis ===");

        FunctionManager funcMgr = currentProgram.getFunctionManager();
        FunctionIterator functions = funcMgr.getFunctions(true);

        String[] licenseKeywords = {
            "license", "activation", "validation", "registration",
            "trial", "expire", "check", "verify", "authenticate"
        };

        while (functions.hasNext() && !monitor.isCancelled()) {
            Function function = functions.next();
            String funcName = function.getName().toLowerCase();

            for (String keyword : licenseKeywords) {
                if (funcName.contains(keyword)) {
                    println(String.format("Found license function: %s at %s",
                                        function.getName(),
                                        function.getEntryPoint()));

                    // Analyze function for patterns
                    analyzeLicenseFunction(function);
                    break;
                }
            }
        }
    }

    private void analyzeLicenseFunction(Function function) throws Exception {
        // Analyze function body for license validation patterns
        InstructionIterator instructions =
            currentProgram.getListing().getInstructions(function.getBody(), true);

        int cryptoOps = 0;
        int stringCompares = 0;
        int networkCalls = 0;

        while (instructions.hasNext() && !monitor.isCancelled()) {
            Instruction instr = instructions.next();
            String mnemonic = instr.getMnemonicString();

            // Count cryptographic operations
            if (mnemonic.equals("XOR") || mnemonic.equals("ROL") ||
                mnemonic.equals("ROR") || mnemonic.equals("SHL")) {
                cryptoOps++;
            }

            // Count string comparisons
            if (mnemonic.equals("CMP") || mnemonic.equals("CMPSB")) {
                stringCompares++;
            }

            // Check for function calls
            if (instr.getFlowType().isCall()) {
                Address[] flows = instr.getFlows();
                for (Address addr : flows) {
                    Function calledFunc = getFunctionAt(addr);
                    if (calledFunc != null) {
                        String calledName = calledFunc.getName().toLowerCase();
                        if (calledName.contains("socket") ||
                            calledName.contains("connect") ||
                            calledName.contains("send")) {
                            networkCalls++;
                        }
                    }
                }
            }
        }

        // Assess function complexity and purpose
        printf("  - Crypto operations: %d\n", cryptoOps);
        printf("  - String comparisons: %d\n", stringCompares);
        printf("  - Network calls: %d\n", networkCalls);

        if (cryptoOps > 5 && stringCompares > 2) {
            println("  [!] Likely license validation routine");
        }

        if (networkCalls > 0) {
            println("  [!] Online license validation detected");
        }
    }

    private void scanLicenseStrings() throws Exception {
        println("\n=== License String Analysis ===");

        MemoryBlock[] blocks = currentProgram.getMemory().getBlocks();

        String[] licensePatterns = {
            "license.*key", "activation.*code", "trial.*period",
            "expire.*date", "registration.*number", "serial.*number",
            "product.*key", "unlock.*code"
        };

        for (MemoryBlock block : blocks) {
            if (block.isInitialized() && block.isRead()) {
                scanBlockForStrings(block, licensePatterns);
            }
        }
    }

    private void scanBlockForStrings(MemoryBlock block, String[] patterns)
            throws Exception {

        Address addr = block.getStart();
        Address end = block.getEnd();

        while (addr.compareTo(end) < 0 && !monitor.isCancelled()) {
            // Look for string data
            Data data = getDataAt(addr);
            if (data != null && data.hasStringValue()) {
                String str = data.getDefaultValueRepresentation().toLowerCase();

                for (String pattern : patterns) {
                    if (str.matches(".*" + pattern + ".*")) {
                        println(String.format("Found license string at %s: %s",
                                            addr, str));
                        break;
                    }
                }
            }

            addr = addr.next();
        }
    }

    private void scanCryptoPatterns() throws Exception {
        println("\n=== Cryptographic Pattern Analysis ===");

        // Look for common cryptographic constants
        long[] cryptoConstants = {
            0x67452301L, // MD5
            0x6A09E667L, // SHA-256
            0x243F6A88L, // Blowfish
            0x9E3779B9L  // TEA
        };

        Memory memory = currentProgram.getMemory();

        for (long constant : cryptoConstants) {
            byte[] bytes = longToBytes(constant);
            Address found = memory.findBytes(
                memory.getMinAddress(),
                bytes,
                null,
                true,
                monitor
            );

            if (found != null) {
                println(String.format("Found crypto constant 0x%X at %s",
                                    constant, found));
            }
        }
    }

    private byte[] longToBytes(long value) {
        byte[] bytes = new byte[4];
        bytes[0] = (byte)(value & 0xFF);
        bytes[1] = (byte)((value >> 8) & 0xFF);
        bytes[2] = (byte)((value >> 16) & 0xFF);
        bytes[3] = (byte)((value >> 24) & 0xFF);
        return bytes;
    }

    private void generateReport() {
        println("\n=== Analysis Complete ===");
        println("License pattern analysis finished.");
        println("Review the findings above for license protection mechanisms.");
    }
}
```

## API Integration

### REST API Development

#### 1. API Endpoint Structure
```python
from flask import Flask, request, jsonify
from intellicrack.core.analysis import AnalysisOrchestrator
from intellicrack.api.auth import require_auth, get_current_user
from intellicrack.api.validation import validate_analysis_request

app = Flask(__name__)

@app.route('/api/v1/analysis', methods=['POST'])
@require_auth
def start_analysis():
    """Start binary analysis via API."""
    try:
        # Validate request
        data = validate_analysis_request(request.json)
        user = get_current_user()

        # Check authorization
        if not user.can_analyze(data['target_path']):
            return jsonify({
                'error': 'Insufficient authorization for target',
                'code': 'UNAUTHORIZED_TARGET'
            }), 403

        # Start analysis
        orchestrator = AnalysisOrchestrator()
        analysis_id = orchestrator.start_analysis_async(
            target_path=data['target_path'],
            analysis_types=data.get('analysis_types', ['static', 'dynamic']),
            options=data.get('options', {}),
            user_id=user.id
        )

        return jsonify({
            'analysis_id': analysis_id,
            'status': 'started',
            'message': 'Analysis started successfully'
        }), 202

    except ValidationError as e:
        return jsonify({
            'error': str(e),
            'code': 'VALIDATION_ERROR'
        }), 400

    except Exception as e:
        logger.error(f"Analysis API error: {e}")
        return jsonify({
            'error': 'Internal server error',
            'code': 'INTERNAL_ERROR'
        }), 500

@app.route('/api/v1/analysis/<analysis_id>', methods=['GET'])
@require_auth
def get_analysis_status(analysis_id):
    """Get analysis status and results."""
    try:
        user = get_current_user()
        orchestrator = AnalysisOrchestrator()

        # Get analysis info
        analysis_info = orchestrator.get_analysis_info(analysis_id)

        # Check ownership
        if analysis_info.user_id != user.id and not user.is_admin():
            return jsonify({
                'error': 'Access denied',
                'code': 'ACCESS_DENIED'
            }), 403

        # Return status and results
        return jsonify({
            'analysis_id': analysis_id,
            'status': analysis_info.status,
            'progress': analysis_info.progress,
            'results': analysis_info.results if analysis_info.completed else None,
            'created_at': analysis_info.created_at.isoformat(),
            'completed_at': analysis_info.completed_at.isoformat() if analysis_info.completed else None
        })

    except AnalysisNotFoundError:
        return jsonify({
            'error': 'Analysis not found',
            'code': 'ANALYSIS_NOT_FOUND'
        }), 404
```

#### 2. WebSocket Integration for Real-time Updates
```python
from flask_socketio import SocketIO, emit, join_room, leave_room
from intellicrack.api.events import AnalysisEventHandler

socketio = SocketIO(app, cors_allowed_origins="*")

class WebSocketAnalysisHandler(AnalysisEventHandler):
    """Handle analysis events for WebSocket clients."""

    def on_analysis_started(self, analysis_id: str, user_id: str):
        """Handle analysis start event."""
        socketio.emit('analysis_started', {
            'analysis_id': analysis_id,
            'timestamp': datetime.utcnow().isoformat()
        }, room=f"user_{user_id}")

    def on_analysis_progress(self, analysis_id: str, user_id: str,
                           progress: int, total: int, step: str):
        """Handle analysis progress event."""
        socketio.emit('analysis_progress', {
            'analysis_id': analysis_id,
            'progress': progress,
            'total': total,
            'step': step,
            'percentage': (progress / total) * 100 if total > 0 else 0
        }, room=f"user_{user_id}")

    def on_analysis_completed(self, analysis_id: str, user_id: str,
                            success: bool, results: dict):
        """Handle analysis completion event."""
        socketio.emit('analysis_completed', {
            'analysis_id': analysis_id,
            'success': success,
            'summary': self.generate_results_summary(results),
            'timestamp': datetime.utcnow().isoformat()
        }, room=f"user_{user_id}")

@socketio.on('connect')
def handle_connect(auth):
    """Handle client connection."""
    user = authenticate_websocket(auth)
    if user:
        join_room(f"user_{user.id}")
        emit('connected', {'status': 'success'})
    else:
        emit('connected', {'status': 'error', 'message': 'Authentication failed'})

@socketio.on('subscribe_analysis')
def handle_subscribe_analysis(data):
    """Subscribe to analysis updates."""
    analysis_id = data.get('analysis_id')
    user = get_current_user()

    # Verify access to analysis
    if verify_analysis_access(analysis_id, user.id):
        join_room(f"analysis_{analysis_id}")
        emit('subscribed', {'analysis_id': analysis_id})
    else:
        emit('error', {'message': 'Access denied'})
```

## VM Framework and Binary Emulation

### Overview

The VM Framework provides comprehensive virtual machine management and binary emulation capabilities for controlled security research and analysis. It integrates QEMU for full system emulation and Qiling for lightweight binary-level emulation, enabling safe testing and modification of binaries in isolated environments.

### Architecture Components

#### 1. QEMUManager Architecture

The `QEMUManager` (located in `intellicrack/ai/qemu_manager.py`) serves as the central controller for all VM operations:

```python
from intellicrack.ai.qemu_manager import QEMUManager

class QEMUManager:
    """Unified QEMU VM management and orchestration.

    Responsibilities:
    - VM lifecycle management (create, start, stop, delete)
    - SSH connection pooling with circuit breaker pattern
    - SFTP file transfer for binary upload/download
    - Snapshot management for testing isolation
    - Configuration integration with centralized config system
    """

    def __init__(self):
        self.config = get_config()
        self.snapshots: Dict[str, QEMUSnapshot] = {}
        self.ssh_pool: Dict[str, SSHClient] = {}
        self.circuit_breaker = CircuitBreaker(
            failure_threshold=self.config.get("vm_framework.ssh.circuit_breaker_threshold", 5),
            timeout=self.config.get("vm_framework.ssh.circuit_breaker_timeout", 60)
        )
```

**Key Features:**
- **Unified Management**: Single point of control for all QEMU operations
- **Connection Pooling**: Reuses SSH connections for efficiency
- **Circuit Breaker**: Prevents cascading failures in SSH connections
- **Snapshot Isolation**: Each test runs in isolated VM snapshot
- **Production-Ready**: Full error handling and recovery mechanisms

#### 2. VMWorkflowManager Design

The `VMWorkflowManager` (located in `intellicrack/core/processing/vm_workflow_manager.py`) orchestrates complete binary analysis workflows:

```python
class VMWorkflowManager:
    """High-level VM workflow orchestration for binary analysis.

    Provides:
    - Complete analysis roundtrip workflow
    - User-controlled file export via dialogs
    - Script execution with OUTPUT_PATH contract
    - Test validation of modifications
    """

    def run_full_analysis_roundtrip(
        self,
        binary_path: str,
        modification_script: str,
        test_script: str,
        platform: str = "windows"
    ) -> Dict[str, Any]:
        """Execute complete binary modification and testing workflow.

        Steps:
        1. Create VM snapshot for isolation
        2. Upload binary to VM
        3. Execute modification script with OUTPUT_PATH
        4. Open file dialog for user to select export location
        5. Download modified binary to user-selected path
        6. Execute test script for validation
        7. Cleanup VM resources
        """
```

### Configuration System Integration

All VM Framework configuration is stored in `config/config.json` under the `vm_framework` section:

```json
{
  "vm_framework": {
    "base_images": {
      "windows": [
        "~/vms/windows10.qcow2",
        "~/vms/windows11.qcow2"
      ],
      "linux": [
        "~/vms/ubuntu22.04.qcow2",
        "~/vms/kali2023.qcow2"
      ],
      "default_windows_size_gb": 2,
      "default_linux_size_gb": 1
    },
    "ssh": {
      "timeout": 30,
      "retry_count": 3,
      "retry_delay": 2,
      "circuit_breaker_threshold": 5,
      "circuit_breaker_timeout": 60
    },
    "qemu_defaults": {
      "memory_mb": 2048,
      "cpu_cores": 2,
      "enable_kvm": true,
      "network_enabled": true,
      "graphics_enabled": false,
      "monitor_port": 55555,
      "ssh_port_start": 22222,
      "vnc_port_start": 5900,
      "timeout": 300,
      "shared_folder_name": "intellicrack_shared_folder"
    },
    "qiling_rootfs": {
      "windows": [
        "~/tools/qiling/rootfs/x86_windows",
        "~/tools/qiling/rootfs/x8664_windows"
      ],
      "linux": [
        "~/tools/qiling/rootfs/x86_linux",
        "~/tools/qiling/rootfs/x8664_linux"
      ]
    }
  }
}
```

**Configuration Usage in Code:**
```python
# QEMUManager uses unified config system
def __init__(self):
    self.config = get_config()

    # Load SSH configuration
    self.ssh_timeout = self.config.get("vm_framework.ssh.timeout", 30)
    self.ssh_retry_count = self.config.get("vm_framework.ssh.retry_count", 3)

    # Load QEMU defaults
    self.default_memory = self.config.get("vm_framework.qemu_defaults.memory_mb", 2048)
    self.default_cores = self.config.get("vm_framework.qemu_defaults.cpu_cores", 2)
```

### SSH Connection Pooling

The framework implements sophisticated SSH connection management:

```python
class SSHConnectionPool:
    """Thread-safe SSH connection pooling with circuit breaker.

    Features:
    - Connection reuse for efficiency
    - Automatic retry with exponential backoff
    - Circuit breaker to prevent cascade failures
    - Connection health checks
    - Automatic cleanup of stale connections
    """

    def get_connection(self, vm_id: str) -> SSHClient:
        """Get or create SSH connection for VM.

        1. Check if connection exists in pool
        2. Validate connection health
        3. Create new connection if needed
        4. Apply circuit breaker logic
        5. Return healthy connection
        """

    def release_connection(self, vm_id: str):
        """Return connection to pool for reuse."""

    def cleanup_stale_connections(self):
        """Remove connections idle > timeout."""
```

**Circuit Breaker Pattern:**
```python
class CircuitBreaker:
    """Prevents repeated connection attempts to failing VMs.

    States:
    - CLOSED: Normal operation, connections allowed
    - OPEN: Too many failures, connections blocked
    - HALF_OPEN: Testing if service recovered
    """

    def call(self, func, *args, **kwargs):
        """Execute function with circuit breaker protection."""
        if self.state == CircuitBreakerState.OPEN:
            if self._timeout_expired():
                self.state = CircuitBreakerState.HALF_OPEN
            else:
                raise CircuitBreakerOpenError("Circuit breaker is OPEN")

        try:
            result = func(*args, **kwargs)
            self._on_success()
            return result
        except Exception as e:
            self._on_failure()
            raise
```

### File Dialog Integration

The framework ensures users always control where modified binaries are saved:

```python
def export_modified_binary(self, remote_path: str) -> str:
    """Export modified binary with user-controlled file dialog.

    NO hardcoded paths - user selects location every time.
    """
    from PyQt6.QtWidgets import QFileDialog, QApplication

    # Ensure QApplication exists
    app = QApplication.instance()
    if not app:
        raise RuntimeError("No QApplication for file dialog")

    # Prepare suggested filename
    original_name = Path(remote_path).name
    suggested_name = f"modified_{original_name}"

    # Create default directory (user can change)
    default_dir = Path.home() / "Documents" / "Intellicrack_Output"
    default_dir.mkdir(parents=True, exist_ok=True)

    # Open file dialog - user selects location
    file_path, _ = QFileDialog.getSaveFileName(
        None,
        "Select Output Location for Modified Binary",
        str(default_dir / suggested_name),
        "Binary Files (*.exe *.bin *.elf *.so *.dll);;All Files (*.*)"
    )

    if not file_path:
        # User cancelled
        return None

    # Download to user-selected location
    success = self.download_file_from_vm(
        snapshot=self.current_snapshot,
        remote_path=remote_path,
        local_path=file_path
    )

    return file_path if success else None
```

### OUTPUT_PATH Contract

Modification scripts MUST follow the OUTPUT_PATH contract:

```bash
#!/bin/bash
# Modification script template

# CRITICAL: The framework sets OUTPUT_PATH environment variable
# Scripts MUST write the modified binary to this location

echo "Input binary: $INPUT_PATH"
echo "Output location: $OUTPUT_PATH"

# Perform modifications
cp "$INPUT_PATH" "$OUTPUT_PATH"

# Apply patches/modifications to OUTPUT_PATH
patch_binary "$OUTPUT_PATH" --remove-checks

# REQUIRED: Verify output was created
if [ ! -f "$OUTPUT_PATH" ]; then
    echo "ERROR: Failed to create output at $OUTPUT_PATH"
    exit 1
fi

echo "Modified binary saved to: $OUTPUT_PATH"
exit 0
```

**Python Script Example:**
```python
#!/usr/bin/env python3
import os
import sys
from pathlib import Path

# Get paths from environment
input_path = os.environ.get('INPUT_PATH')
output_path = os.environ.get('OUTPUT_PATH')

if not input_path or not output_path:
    print("ERROR: INPUT_PATH and OUTPUT_PATH must be set")
    sys.exit(1)

# Read original binary
with open(input_path, 'rb') as f:
    binary_data = f.read()

# Apply modifications
modified_data = apply_patches(binary_data)

# Write to OUTPUT_PATH
with open(output_path, 'wb') as f:
    f.write(modified_data)

print(f"Modified binary written to: {output_path}")
```

### Adding New Base Images

To add new VM base images for testing:

#### 1. Update Configuration
Edit `config/config.json`:
```json
{
  "vm_framework": {
    "base_images": {
      "windows": [
        "~/vms/windows10.qcow2",
        "~/vms/windows11.qcow2",
        "~/vms/windows_server_2022.qcow2"  // New image
      ],
      "linux": [
        "~/vms/ubuntu22.04.qcow2",
        "~/vms/kali2023.qcow2",
        "~/vms/debian12.qcow2"  // New image
      ]
    }
  }
}
```

#### 2. Prepare Base Image
```bash
# Create QEMU image
qemu-img create -f qcow2 debian12.qcow2 20G

# Install OS with SSH enabled
qemu-system-x86_64 \
  -hda debian12.qcow2 \
  -cdrom debian-12.iso \
  -m 2048 \
  -enable-kvm \
  -boot d

# Configure SSH in guest OS
# 1. Install openssh-server
# 2. Enable root login or create user
# 3. Configure SSH keys
```

#### 3. Image Requirements
Base images must have:
- **SSH Server**: OpenSSH installed and enabled
- **Python 3**: For script execution
- **Network**: Configured for host-only networking
- **Tools**: Basic development tools (gcc, make, etc.)

### Snapshot Management

The framework uses QEMU snapshots for test isolation:

```python
class SnapshotManager:
    """Manages QEMU VM snapshots for test isolation.

    Each test runs in isolated snapshot that's deleted after use.
    """

    def create_snapshot(self, vm_id: str, binary_path: str) -> QEMUSnapshot:
        """Create snapshot for binary testing.

        1. Clone base image
        2. Start VM
        3. Configure networking
        4. Setup SSH access
        5. Return snapshot handle
        """

    def cleanup_snapshot(self, snapshot_id: str):
        """Clean up snapshot after testing.

        1. Stop VM if running
        2. Close SSH connections
        3. Delete snapshot disk
        4. Release resources
        """
```

**Snapshot Lifecycle:**
```python
# Create snapshot for test
snapshot = qemu_manager.create_script_test_snapshot(
    binary_path="malware.exe",
    modification_script="remove_trial.sh",
    test_script="verify_unlimited.py",
    platform="windows"
)

try:
    # Use snapshot for testing
    result = qemu_manager.test_script_in_vm(
        snapshot=snapshot,
        script_content=modification_script,
        remote_binary_path="/tmp/malware.exe"
    )
finally:
    # Always cleanup
    qemu_manager.cleanup_snapshot(snapshot.snapshot_id)
```

### Qiling Integration

For lightweight emulation without full VMs:

```python
from intellicrack.core.processing.qiling_emulator import QilingEmulator

class QilingIntegration:
    """Lightweight binary emulation using Qiling framework.

    Use cases:
    - Quick API behavior analysis
    - Memory access monitoring
    - License check detection
    - Faster than full VM for simple cases
    """

    def __init__(self):
        self.config = get_config()
        # Load Qiling rootfs paths from config
        self.rootfs_paths = self.config.get("vm_framework.qiling_rootfs", {})

    def emulate_binary(self, binary_path: str, options: Dict):
        """Run lightweight emulation.

        Automatically detects architecture and OS,
        selects appropriate rootfs from config.
        """
        emulator = QilingEmulator(
            binary_path=binary_path,
            rootfs=self._get_rootfs(binary_path),
            verbose=options.get("verbose", False)
        )

        # Add hooks for analysis
        emulator.add_license_detection_hooks()

        # Run emulation
        return emulator.run(timeout=60)
```

### Error Handling and Recovery

The framework implements comprehensive error handling:

```python
class VMErrorHandler:
    """Centralized error handling for VM operations.

    Handles:
    - VM startup failures
    - SSH connection errors
    - File transfer failures
    - Script execution errors
    - Resource exhaustion
    """

    def handle_vm_error(self, error: Exception, context: Dict):
        """Handle VM-related errors with recovery.

        Recovery strategies:
        1. Retry with exponential backoff
        2. Fallback to alternative VM
        3. Clean up and report failure
        """

        if isinstance(error, SSHConnectionError):
            return self._handle_ssh_error(error, context)
        elif isinstance(error, VMStartupError):
            return self._handle_startup_error(error, context)
        elif isinstance(error, ResourceExhaustedError):
            return self._handle_resource_error(error, context)
        else:
            # Log and cleanup
            logger.error(f"Unhandled VM error: {error}")
            self._cleanup_failed_vm(context)
            raise
```

### Performance Considerations

#### Connection Pooling Benefits
- **Reduced Overhead**: Reuse SSH connections instead of creating new ones
- **Lower Latency**: Pre-established connections ready for use
- **Resource Efficiency**: Fewer system resources consumed

#### Snapshot Optimization
- **Copy-on-Write**: QEMU qcow2 format only stores changes
- **Parallel Testing**: Run multiple snapshots simultaneously
- **Fast Cleanup**: Delete snapshot = delete diff file

#### Best Practices
1. **Limit Concurrent VMs**: Based on available RAM
2. **Use Qiling for Simple Cases**: Faster than full VM
3. **Cache Base Images**: Store on SSD for fast cloning
4. **Monitor Resources**: Track CPU/RAM usage
5. **Implement Timeouts**: Prevent hanging operations

### Security Considerations

#### SSH Key Management
- Keys stored in environment variables via Secrets Manager
- Never hardcoded in source code
- Rotated regularly
- Unique per VM instance

#### Network Isolation
- Host-only networking by default
- No internet access for test VMs
- Port forwarding only for SSH/VNC
- Firewall rules to restrict access

#### Resource Limits
- Memory limits per VM
- CPU core restrictions
- Disk quota enforcement
- Concurrent VM limits

## Testing Framework

### Unit Testing

#### 1. Test Structure
```python
import pytest
from unittest.mock import Mock, patch, MagicMock
from intellicrack.core.analysis.binary_analyzer import BinaryAnalyzer
from intellicrack.core.analysis.exceptions import AnalysisError

class TestBinaryAnalyzer:
    """Test suite for BinaryAnalyzer."""

    @pytest.fixture
    def analyzer(self):
        """Create analyzer instance for testing."""
        return BinaryAnalyzer()

    @pytest.fixture
    def sample_pe_file(self, tmp_path):
        """Create sample PE file for testing."""
        pe_content = b"MZ\x90\x00" + b"\x00" * 60 + b"PE\x00\x00"
        pe_file = tmp_path / "sample.exe"
        pe_file.write_bytes(pe_content)
        return str(pe_file)

    def test_analyze_valid_pe_file(self, analyzer, sample_pe_file):
        """Test analysis of valid PE file."""
        result = analyzer.analyze(sample_pe_file)

        assert result.success
        assert result.file_format == "PE"
        assert result.file_size > 0
        assert "sections" in result.metadata

    def test_analyze_nonexistent_file(self, analyzer):
        """Test analysis of nonexistent file."""
        with pytest.raises(AnalysisError) as exc_info:
            analyzer.analyze("/nonexistent/file.exe")

        assert "File not found" in str(exc_info.value)

    @patch('intellicrack.core.analysis.binary_analyzer.pefile.PE')
    def test_analyze_with_pefile_error(self, mock_pe, analyzer, sample_pe_file):
        """Test handling of pefile errors."""
        mock_pe.side_effect = Exception("Invalid PE file")

        result = analyzer.analyze(sample_pe_file)

        assert not result.success
        assert "Invalid PE file" in result.error_message

    def test_get_file_info(self, analyzer, sample_pe_file):
        """Test file information extraction."""
        info = analyzer.get_file_info(sample_pe_file)

        assert info["file_size"] > 0
        assert info["file_type"] == "PE"
        assert "md5_hash" in info
        assert "sha256_hash" in info

    @pytest.mark.parametrize("file_content,expected_format", [
        (b"MZ\x90\x00", "PE"),
        (b"\x7fELF", "ELF"),
        (b"\xfe\xed\xfa\xce", "Mach-O"),
        (b"PK\x03\x04", "ZIP/APK")
    ])
    def test_detect_file_format(self, analyzer, tmp_path, file_content, expected_format):
        """Test file format detection."""
        test_file = tmp_path / "test_file"
        test_file.write_bytes(file_content + b"\x00" * 100)

        format_detected = analyzer.detect_file_format(str(test_file))
        assert format_detected == expected_format
```

#### 2. Integration Testing
```python
import pytest
import tempfile
import shutil
from pathlib import Path
from intellicrack.core.analysis import AnalysisOrchestrator
from intellicrack.ai.ai_script_generator import AIScriptGenerator

class TestIntegration:
    """Integration tests for core components."""

    @pytest.fixture(scope="class")
    def test_environment(self):
        """Set up test environment."""
        test_dir = tempfile.mkdtemp()

        # Create test files
        test_binary = Path(test_dir) / "test_app.exe"
        test_binary.write_bytes(self.create_test_pe_binary())

        yield {
            "test_dir": test_dir,
            "test_binary": str(test_binary)
        }

        # Cleanup
        shutil.rmtree(test_dir)

    def create_test_pe_binary(self) -> bytes:
        """Create minimal valid PE binary for testing."""
        # Minimal PE header
        dos_header = b"MZ\x90\x00" + b"\x00" * 56 + b"\x80\x00\x00\x00"
        pe_header = b"PE\x00\x00"
        file_header = b"\x4c\x01\x01\x00" + b"\x00" * 16  # Basic file header
        optional_header = b"\x0b\x01" + b"\x00" * 222  # Basic optional header

        return dos_header + b"\x00" * 64 + pe_header + file_header + optional_header

    def test_end_to_end_analysis(self, test_environment):
        """Test complete analysis workflow."""
        # Initialize components
        orchestrator = AnalysisOrchestrator()
        ai_generator = AIScriptGenerator()

        # Perform analysis
        analysis_result = orchestrator.analyze_binary(
            test_environment["test_binary"]
        )

        # Verify analysis results
        assert analysis_result.success
        assert len(analysis_result.phases_completed) > 0
        assert "basic_info" in analysis_result.results

        # Generate AI script based on analysis
        script_result = ai_generator.generate_script_from_analysis(
            analysis_result=analysis_result,
            script_type="frida"
        )

        # Verify script generation
        assert script_result.success
        assert len(script_result.script.content) > 0
        assert script_result.script.language == "javascript"

    def test_plugin_integration(self, test_environment):
        """Test plugin system integration."""
        from intellicrack.plugins import PluginManager

        plugin_manager = PluginManager()

        # Load test plugin
        test_plugin_path = Path(__file__).parent / "test_plugins" / "test_plugin.py"
        success = plugin_manager.load_plugin(str(test_plugin_path))

        assert success
        assert "TestPlugin" in plugin_manager.get_loaded_plugins()

        # Execute plugin
        result = plugin_manager.execute_plugin(
            "TestPlugin",
            target_file=test_environment["test_binary"]
        )

        assert result.success
        assert "test_results" in result.data
```

### Performance Testing

#### 1. Performance Benchmarks
```python
import pytest
import time
import psutil
import threading
from intellicrack.core.analysis import AnalysisOrchestrator

class TestPerformance:
    """Performance tests for core components."""

    def test_analysis_performance(self, sample_binaries):
        """Test analysis performance across different binary sizes."""
        orchestrator = AnalysisOrchestrator()

        performance_results = []

        for binary_info in sample_binaries:
            start_time = time.time()
            start_memory = psutil.Process().memory_info().rss

            # Perform analysis
            result = orchestrator.analyze_binary(binary_info["path"])

            end_time = time.time()
            end_memory = psutil.Process().memory_info().rss

            performance_results.append({
                "file_size": binary_info["size"],
                "analysis_time": end_time - start_time,
                "memory_usage": end_memory - start_memory,
                "success": result.success
            })

        # Verify performance criteria
        for result in performance_results:
            # Analysis should complete within reasonable time
            max_time = result["file_size"] / (1024 * 1024) * 30  # 30s per MB
            assert result["analysis_time"] < max_time

            # Memory usage should be reasonable
            max_memory = result["file_size"] * 5  # 5x file size max
            assert result["memory_usage"] < max_memory

    def test_concurrent_analysis(self, sample_binaries):
        """Test concurrent analysis performance."""
        orchestrator = AnalysisOrchestrator()
        results = []
        threads = []

        def analyze_binary(binary_path):
            start_time = time.time()
            result = orchestrator.analyze_binary(binary_path)
            end_time = time.time()

            results.append({
                "path": binary_path,
                "time": end_time - start_time,
                "success": result.success
            })

        # Start concurrent analyses
        for binary_info in sample_binaries[:5]:  # Test with 5 concurrent
            thread = threading.Thread(
                target=analyze_binary,
                args=(binary_info["path"],)
            )
            threads.append(thread)
            thread.start()

        # Wait for completion
        for thread in threads:
            thread.join(timeout=300)  # 5 minute timeout

        # Verify all completed successfully
        assert len(results) == 5
        assert all(result["success"] for result in results)

        # Verify reasonable performance degradation
        avg_time = sum(result["time"] for result in results) / len(results)
        assert avg_time < 120  # Should complete within 2 minutes on average
```

## Code Quality and Standards

### Code Style and Formatting

#### 1. Python Code Standards
```python
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/psf/black
    rev: 23.1.0
    hooks:
      - id: black
        language_version: python3.11

  - repo: https://github.com/pycqa/isort
    rev: 5.12.0
    hooks:
      - id: isort
        args: ["--profile", "black"]

  - repo: https://github.com/pycqa/flake8
    rev: 6.0.0
    hooks:
      - id: flake8
        args: ["--max-line-length=88", "--extend-ignore=E203,W503"]

  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v1.0.1
    hooks:
      - id: mypy
        additional_dependencies: [types-requests, types-PyYAML]
```

#### 2. Documentation Standards
```python
def analyze_binary(
    self,
    binary_path: str,
    analysis_options: Optional[Dict[str, Any]] = None,
    timeout: int = 300
) -> AnalysisResult:
    """Perform comprehensive binary analysis.

    This method orchestrates multiple analysis engines to provide comprehensive
    insights into the target binary, including static analysis, dynamic analysis,
    protection detection, and vulnerability assessment.

    Args:
        binary_path: Absolute path to the binary file to analyze.
        analysis_options: Optional configuration for analysis engines.
            Keys can include:
            - 'static_analysis': bool - Enable static analysis (default: True)
            - 'dynamic_analysis': bool - Enable dynamic analysis (default: True)
            - 'protection_detection': bool - Enable protection detection (default: True)
            - 'vulnerability_scan': bool - Enable vulnerability scanning (default: True)
        timeout: Maximum time in seconds for analysis completion (default: 300).

    Returns:
        AnalysisResult containing comprehensive analysis findings including:
        - File format and metadata
        - Detected protection mechanisms
        - Security vulnerabilities
        - Behavioral analysis results
        - AI-generated insights and recommendations

    Raises:
        FileNotFoundError: If the specified binary file does not exist.
        PermissionError: If insufficient permissions to read the binary file.
        AnalysisTimeoutError: If analysis exceeds the specified timeout.
        UnsupportedFormatError: If the binary format is not supported.

    Example:
        >>> analyzer = BinaryAnalyzer()
        >>> result = analyzer.analyze_binary(
        ...     "/path/to/protected_app.exe",
        ...     analysis_options={"dynamic_analysis": False},
        ...     timeout=600
        ... )
        >>> if result.success:
        ...     print(f"Detected protections: {result.protections}")
        ...     print(f"Vulnerabilities found: {len(result.vulnerabilities)}")

    Note:
        This method requires proper authorization to analyze the target binary.
        Ensure you have legal permission to analyze the specified file.
        All analysis is performed in an isolated environment for security.
    """
```

### Type Hints and Validation

```python
from typing import Dict, List, Optional, Union, Any, Protocol
from dataclasses import dataclass
from pydantic import BaseModel, validator

# Pydantic models for validation
class AnalysisConfig(BaseModel):
    """Configuration for binary analysis."""

    target_path: str
    analysis_types: List[str] = ["static", "dynamic"]
    timeout: int = 300
    max_memory: str = "2GB"
    sandbox_mode: bool = True

    @validator('target_path')
    def validate_target_path(cls, v):
        if not os.path.exists(v):
            raise ValueError(f"Target file does not exist: {v}")
        return v

    @validator('analysis_types')
    def validate_analysis_types(cls, v):
        valid_types = {"static", "dynamic", "entropy", "vulnerability"}
        invalid_types = set(v) - valid_types
        if invalid_types:
            raise ValueError(f"Invalid analysis types: {invalid_types}")
        return v

    @validator('timeout')
    def validate_timeout(cls, v):
        if v <= 0 or v > 3600:  # Max 1 hour
            raise ValueError("Timeout must be between 1 and 3600 seconds")
        return v

# Protocol definitions for interfaces
class AnalysisEngine(Protocol):
    """Protocol for analysis engines."""

    def analyze(self, target: str, options: Dict[str, Any]) -> AnalysisResult:
        """Perform analysis on target."""
        ...

    def get_capabilities(self) -> List[str]:
        """Get engine capabilities."""
        ...

    def validate_target(self, target: str) -> bool:
        """Validate if target is supported."""
        ...

# Dataclasses for structured data
@dataclass
class VulnerabilityInfo:
    """Information about a discovered vulnerability."""

    id: str
    type: str
    severity: str
    description: str
    location: str
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    remediation: Optional[str] = None
    references: List[str] = field(default_factory=list)

    def __post_init__(self):
        """Validate data after initialization."""
        if self.severity not in ["low", "medium", "high", "critical"]:
            raise ValueError(f"Invalid severity: {self.severity}")

        if self.cvss_score is not None and not (0.0 <= self.cvss_score <= 10.0):
            raise ValueError(f"Invalid CVSS score: {self.cvss_score}")
```

## Contribution Guidelines

### Development Process

#### 1. Feature Development Workflow
```bash
# 1. Create feature branch
git checkout -b feature/new-analysis-engine

# 2. Implement feature with tests
# - Write tests first (TDD approach)
# - Implement feature
# - Ensure all tests pass

# 3. Run quality checks
black intellicrack/
isort intellicrack/
flake8 intellicrack/
mypy intellicrack/

# 4. Run full test suite
pytest tests/ --cov=intellicrack

# 5. Update documentation
# - Update API documentation
# - Update user guides if needed
# - Update CHANGELOG.md

# 6. Create pull request
git push origin feature/new-analysis-engine
# Create PR via GitHub/GitLab
```

#### 2. Code Review Guidelines
```yaml
# .github/pull_request_template.md
## Description
Brief description of changes made.

## Type of Change
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Performance tests added/updated (if applicable)
- [ ] All tests pass locally

## Security Considerations
- [ ] Changes reviewed for security implications
- [ ] No sensitive information exposed
- [ ] Authorization checks implemented where needed
- [ ] Input validation implemented

## Documentation
- [ ] Code is self-documenting with clear variable names
- [ ] Complex logic is commented
- [ ] API documentation updated
- [ ] User documentation updated (if applicable)

## Checklist
- [ ] Code follows project style guidelines
- [ ] Self-review of code completed
- [ ] Changes generate no new warnings
- [ ] Any dependent changes have been merged and published
```

### Security Review Process

#### 1. Security Checklist
```python
# Security review checklist for code changes

class SecurityReviewChecklist:
    """Security review checklist for code changes."""

    INPUT_VALIDATION = [
        "All user inputs are validated",
        "File paths are sanitized",
        "SQL injection prevention implemented",
        "Command injection prevention implemented",
        "Input size limits enforced"
    ]

    AUTHORIZATION = [
        "Authorization checks implemented",
        "Principle of least privilege followed",
        "Resource access controls verified",
        "User permissions validated"
    ]

    DATA_PROTECTION = [
        "Sensitive data identified and protected",
        "Encryption used for sensitive data",
        "Secure data transmission",
        "Proper data disposal",
        "No hardcoded secrets"
    ]

    ERROR_HANDLING = [
        "Secure error handling implemented",
        "No sensitive information in error messages",
        "Proper logging without sensitive data",
        "Graceful failure handling"
    ]

    DEPENDENCIES = [
        "Dependencies scanned for vulnerabilities",
        "Only necessary dependencies included",
        "Dependencies regularly updated",
        "License compatibility verified"
    ]

# Automated security checks
def run_security_checks():
    """Run automated security checks."""

    # Static analysis security testing
    subprocess.run(["bandit", "-r", "intellicrack/"], check=True)

    # Dependency vulnerability scanning
    subprocess.run(["safety", "check"], check=True)

    # Secret scanning
    subprocess.run(["detect-secrets", "scan", "--all-files"], check=True)

    # License compliance check
    subprocess.run(["pip-licenses", "--format=json"], check=True)
```

## Performance Optimization

### Profiling and Monitoring

#### 1. Performance Profiling
```python
import cProfile
import pstats
from functools import wraps
from typing import Callable

def profile_performance(func: Callable) -> Callable:
    """Decorator for performance profiling."""

    @wraps(func)
    def wrapper(*args, **kwargs):
        profiler = cProfile.Profile()
        profiler.enable()

        try:
            result = func(*args, **kwargs)
            return result
        finally:
            profiler.disable()

            # Save profiling results
            stats = pstats.Stats(profiler)
            stats.sort_stats('cumulative')
            stats.dump_stats(f"/tmp/profile_{func.__name__}.prof")

            # Log top time consumers
            stats.print_stats(10)

    return wrapper

# Usage
@profile_performance
def analyze_large_binary(self, binary_path: str) -> AnalysisResult:
    """Analyze large binary with performance profiling."""
    return self.perform_analysis(binary_path)
```

#### 2. Memory Optimization
```python
import gc
import weakref
from typing import Dict, Any

class ResourceManager:
    """Manage resources and memory usage."""

    def __init__(self, max_memory_mb: int = 2048):
        self.max_memory_mb = max_memory_mb
        self.active_analyses: Dict[str, weakref.ref] = {}
        self.memory_monitor = MemoryMonitor()

    def start_analysis(self, analysis_id: str, analyzer: Any) -> bool:
        """Start analysis with memory monitoring."""

        # Check current memory usage
        current_memory = self.memory_monitor.get_current_usage_mb()

        if current_memory > self.max_memory_mb * 0.8:  # 80% threshold
            # Attempt garbage collection
            gc.collect()
            current_memory = self.memory_monitor.get_current_usage_mb()

            if current_memory > self.max_memory_mb * 0.9:  # 90% threshold
                logger.warning("Memory usage high, deferring analysis")
                return False

        # Register analysis with weak reference
        self.active_analyses[analysis_id] = weakref.ref(analyzer)

        return True

    def cleanup_completed_analyses(self):
        """Clean up completed analyses."""
        # Remove dead weak references
        dead_refs = [
            analysis_id for analysis_id, ref in self.active_analyses.items()
            if ref() is None
        ]

        for analysis_id in dead_refs:
            del self.active_analyses[analysis_id]

        # Force garbage collection
        gc.collect()

class MemoryMonitor:
    """Monitor memory usage."""

    def get_current_usage_mb(self) -> float:
        """Get current memory usage in MB."""
        import psutil
        process = psutil.Process()
        return process.memory_info().rss / (1024 * 1024)

    def get_memory_breakdown(self) -> Dict[str, float]:
        """Get detailed memory breakdown."""
        import tracemalloc

        if not tracemalloc.is_tracing():
            tracemalloc.start()

        snapshot = tracemalloc.take_snapshot()
        top_stats = snapshot.statistics('lineno')

        breakdown = {}
        for stat in top_stats[:10]:
            key = f"{stat.traceback.format()[-1]}"
            breakdown[key] = stat.size / (1024 * 1024)  # Convert to MB

        return breakdown
```

---

This comprehensive developer guide provides the foundation for effective development, extension, and contribution to the Intellicrack platform. By following these guidelines and utilizing the provided patterns and tools, developers can create high-quality, secure, and performant additions to the platform while maintaining consistency with the existing codebase and architecture.
