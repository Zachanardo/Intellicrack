# ICP Integration Architecture

Comprehensive architectural documentation for the ICP (Intellicrack Protection) Engine integration with die-python.

## Overview

The ICP integration represents a complete modernization of Intellicrack's protection detection capabilities, replacing the legacy DIE (Detect-It-Easy) engine with native die-python integration. This architecture provides enhanced performance, maintainability, and extensibility while maintaining full backward compatibility.

## System Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Intellicrack GUI Layer                   │
├─────────────────────────────────────────────────────────────┤
│  Main Window  │  Protection Analysis  │  Analysis Result   │
│     (UI)      │       Widget          │   Orchestrator    │
├─────────────────────────────────────────────────────────────┤
│                   Integration Layer                         │
│  ┌───────────────┐  ┌─────────────────┐  ┌──────────────┐  │
│  │ Auto-Trigger  │  │  Signal/Slot    │  │   Handler    │  │
│  │   System      │  │  Communication  │  │   Registry   │  │
│  └───────────────┘  └─────────────────┘  └──────────────┘  │
├─────────────────────────────────────────────────────────────┤
│                    ICP Backend Layer                        │
│  ┌───────────────┐  ┌─────────────────┐  ┌──────────────┐  │
│  │  ICPBackend   │  │   ScanResult    │  │   Detection  │  │
│  │   (Core)      │  │   Processing    │  │   Analysis   │  │
│  └───────────────┘  └─────────────────┘  └──────────────┘  │
├─────────────────────────────────────────────────────────────┤
│                  die-python Interface                       │
│  ┌───────────────┐  ┌─────────────────┐  ┌──────────────┐  │
│  │ Native Bindings│  │  Text Parser   │  │  Scan Flags  │  │
│  │   (v0.4.0)    │  │                │  │   Management │  │
│  └───────────────┘  └─────────────────┘  └──────────────┘  │
├─────────────────────────────────────────────────────────────┤
│                      DIE Engine                             │
│              Detect-It-Easy v3.09 (Native)                 │
└─────────────────────────────────────────────────────────────┘
```

### Component Interaction Flow

```
File Selection → Auto-Trigger → ICP Backend → die-python → Results → GUI Update
     ↓              ↓             ↓            ↓          ↓         ↓
  Main Window   File Monitor   Async Scan   Native Lib  Parser   Widget
     │              │             │            │          │         │
     ├──────────────┴─────────────┤            │          │         │
     │         Signal Emission    │            │          │         │
     │                           │            │          │         │
     └───────────────────────────┴────────────┴──────────┴─────────┘
                        Result Distribution & Handler Notification
```

## Core Components

### 1. ICP Backend (`intellicrack.protection.icp_backend`)

**Purpose**: Native die-python integration and analysis orchestration

**Key Features**:
- Asynchronous file analysis with timeout handling
- Multiple scan modes (NORMAL, DEEP, HEURISTIC, AGGRESSIVE, ALL)
- Batch processing with concurrency control
- Structured result parsing from die-python text output
- Singleton pattern for resource management

**Architecture Pattern**: Facade + Singleton
- Facades die-python complexity behind simple async API
- Singleton ensures single instance across application

### 2. Protection Analysis Widget (`intellicrack.ui.widgets.icp_analysis_widget`)

**Purpose**: GUI component for protection analysis display and interaction

**Key Features**:
- Real-time analysis status updates
- Interactive scan mode selection
- Structured results display with categorization
- Error handling and user feedback
- Progress indication for long-running analyses

**Architecture Pattern**: Model-View-Controller (MVC)
- View: PyQt5 widgets and layouts
- Controller: Signal/slot event handling
- Model: ICPScanResult data binding

### 3. Analysis Result Orchestrator (`intellicrack.analysis.analysis_result_orchestrator`)

**Purpose**: Central coordination hub for analysis result distribution

**Key Features**:
- Handler registration and management
- Result distribution to multiple consumers
- Signal emission for status updates
- Error isolation and propagation
- Integration with existing analysis workflows

**Architecture Pattern**: Observer + Mediator
- Observer: Handlers subscribe to analysis events
- Mediator: Centralized communication hub

### 4. Auto-Trigger System (`intellicrack.ui.main_window`)

**Purpose**: Automatic analysis initiation when files are opened

**Key Features**:
- File open event detection
- Automatic ICP analysis triggering
- Tab switching to Protection Analysis view
- Integration with existing file handling

**Architecture Pattern**: Event-Driven
- Responds to file open events
- Triggers analysis workflow automatically

## Data Flow Architecture

### Analysis Workflow

```
┌─────────────┐    ┌──────────────┐    ┌─────────────┐
│   File      │    │   ICP        │    │ die-python  │
│   Input     │───▶│  Backend     │───▶│   Engine    │
└─────────────┘    └──────────────┘    └─────────────┘
                           │                    │
                           ▼                    ▼
┌─────────────┐    ┌──────────────┐    ┌─────────────┐
│   Result    │◀───│    Text      │◀───│   Native    │
│ Processing  │    │   Parsing    │    │   Output    │
└─────────────┘    └──────────────┘    └─────────────┘
       │
       ▼
┌─────────────┐    ┌──────────────┐    ┌─────────────┐
│  Handler    │◀───│ Orchestrator │◀───│  Structured │
│Distribution │    │              │    │   Results   │
└─────────────┘    └──────────────┘    └─────────────┘
```

### Data Transformation Pipeline

1. **Input Stage**: File path validation and preparation
2. **Analysis Stage**: die-python engine execution with scan flags
3. **Parsing Stage**: Text output → Structured data conversion
4. **Processing Stage**: Result validation and enrichment
5. **Distribution Stage**: Handler notification and GUI updates

## Integration Patterns

### 1. Async/Await Integration

**Pattern**: Task-based asynchronous programming
```python
# Non-blocking analysis execution
async def analyze_file(self, file_path: str) -> ICPScanResult:
    # Execute in thread pool to avoid blocking GUI
    result = await asyncio.get_event_loop().run_in_executor(
        None, self._scan_file, file_path
    )
    return self._process_result(result)
```

**Benefits**:
- Non-blocking GUI operations
- Concurrent analysis capability
- Timeout handling and cancellation
- Resource efficiency

### 2. Signal/Slot Communication

**Pattern**: Event-driven communication with PyQt5 signals
```python
class ICPAnalysisWidget(QWidget):
    analysis_complete = pyqtSignal(object)  # ICPScanResult
    analysis_error = pyqtSignal(str)

    def analyze_file(self, file_path: str):
        # Start background analysis
        self.analysis_thread.start_analysis(file_path)
```

**Benefits**:
- Loose coupling between components
- Thread-safe GUI updates
- Event propagation across layers
- Error isolation

### 3. Singleton Backend Management

**Pattern**: Single instance with lazy initialization
```python
_icp_backend: Optional[ICPBackend] = None

def get_icp_backend() -> ICPBackend:
    global _icp_backend
    if _icp_backend is None:
        _icp_backend = ICPBackend()
    return _icp_backend
```

**Benefits**:
- Resource conservation
- Consistent state management
- die-python library initialization optimization
- Memory efficiency

## Text Processing Architecture

### die-python Output Format

**Input Format** (die.scan_file output):
```
PE64
    Unknown: Unknown
    Packer: UPX
    Protector: VMProtect
```

**Processing Pipeline**:
1. **Line Splitting**: Split by newlines, handle empty lines
2. **Header Parsing**: First line = file type (PE64, ELF64, etc.)
3. **Detection Parsing**: Indented lines = "Type: Name" format
4. **Structured Creation**: Build ICPDetection → ICPFileInfo → ICPScanResult

### Parser Implementation

```python
def from_die_text(cls, file_path: str, die_text: str) -> 'ICPScanResult':
    # Stage 1: Input validation and preprocessing
    lines = native_engine_text.strip().split('\n') if native_engine_text else []

    # Stage 2: File type extraction
    filetype = lines[0].strip() if lines else "Binary"

    # Stage 3: Detection extraction and parsing
    for line in lines[1:]:
        if ':' in line:
            type_part, name_part = line.split(':', 1)
            # Create structured detection object

    # Stage 4: Result assembly
    return ICPScanResult(file_path, [file_info])
```

## Performance Architecture

### Concurrency Model

**Thread Pool Execution**:
- GUI thread remains responsive
- die-python execution in worker threads
- Configurable concurrency limits
- Automatic resource cleanup

**Memory Management**:
- Lazy loading of die-python library
- Result object pooling for batch operations
- Automatic garbage collection of temporary data
- Minimal memory footprint per analysis

### Performance Optimizations

1. **Scan Flag Optimization**: Direct flag mapping to avoid string parsing
2. **Result Caching**: Optional caching for repeated analyses
3. **Batch Processing**: Optimized concurrent execution
4. **Timeout Management**: Prevents resource leaks from hung analyses

## Error Handling Architecture

### Error Categories

1. **Initialization Errors**: die-python library not available
2. **Analysis Errors**: File access, timeout, or parsing failures
3. **Integration Errors**: Signal/slot communication issues
4. **System Errors**: Resource exhaustion or platform issues

### Error Propagation Pattern

```
die-python Error → ICPBackend → Result Object → Orchestrator → Handler → GUI
     │              │           │               │             │        │
     ▼              ▼           ▼               ▼             ▼        ▼
  Exception     Log + Wrap   Error Field    Error Signal   Error UI  User Alert
```

### Recovery Mechanisms

- **Graceful Degradation**: Continue operation with limited functionality
- **Retry Logic**: Automatic retry for transient failures
- **Fallback Options**: Alternative analysis methods when available
- **User Notification**: Clear error messages and suggested actions

## Security Architecture

### Input Validation

- File path sanitization and validation
- Size limits for analysis targets
- Permission checking before analysis
- Malformed input handling

### Resource Protection

- Timeout enforcement for all operations
- Memory usage monitoring and limits
- Process isolation through thread pools
- Automatic cleanup on failure

### Error Information Disclosure

- Sanitized error messages for users
- Detailed logging for debugging
- No sensitive path information in errors
- Secure handling of analysis failures

## Extension Architecture

### Plugin Integration Points

1. **Custom Scan Modes**: Additional die-python flag configurations
2. **Result Processors**: Custom detection classification logic
3. **Output Formatters**: Alternative result presentation
4. **Analysis Handlers**: Custom response to analysis completion

### API Extension Pattern

```python
class CustomICPHandler:
    def on_icp_analysis_complete(self, result: ICPScanResult):
        # Custom processing logic
        custom_analysis = self.process_detections(result.all_detections)

    def register_with_orchestrator(self, orchestrator: AnalysisResultOrchestrator):
        orchestrator.register_handler(self)
```

## Deployment Architecture

### Dependency Management

**Required Dependencies**:
- die-python (v0.4.0+): Core analysis engine
- nanobind: die-python binding dependency
- PyQt5: GUI framework for signals/slots

**Optional Dependencies**:
- psutil: System resource monitoring
- asyncio: Enhanced async capabilities (Python 3.11+)

### Environment Requirements

**Development Environment**:
- Python 3.11+ with asyncio support
- Virtual environment with die-python installed
- Development tools for building extensions

**Production Environment**:
- Stable Python 3.11+ runtime
- die-python properly installed and accessible
- Sufficient memory for concurrent analyses (8GB+ recommended)

## Migration Architecture

### Legacy Compatibility

**Maintained Interfaces**:
- `show_entropy` and `show_info` parameters (ignored but accepted)
- JSON output format in `raw_json` field
- Existing error handling patterns

**Breaking Changes**:
- Synchronous → Asynchronous API
- String output → Structured objects
- Single-threaded → Multi-threaded execution

### Migration Path

1. **Phase 1**: Install die-python alongside legacy DIE
2. **Phase 2**: Update calling code to use async patterns
3. **Phase 3**: Replace legacy DIE calls with ICP backend
4. **Phase 4**: Remove legacy DIE dependencies

## Testing Architecture

### Test Coverage Strategy

**Unit Tests**:
- ICPBackend API functionality
- Text parsing accuracy
- Error handling robustness
- Scan mode flag mapping

**Integration Tests**:
- GUI widget interaction
- Signal/slot communication
- Orchestrator distribution
- End-to-end analysis workflow

**Performance Tests**:
- Analysis speed benchmarks
- Memory usage validation
- Concurrency limits testing
- Timeout behavior verification

### Test Environment

**Isolated Testing**:
- Dedicated virtual environment
- Test binary samples
- Mock die-python output
- Controlled error conditions

**Validation Framework**:
- Automated test execution
- Performance regression detection
- Integration validation
- Documentation synchronization

## Future Architecture Considerations

### Scalability Enhancements

- Distributed analysis across multiple machines
- Result caching and persistence
- API rate limiting and throttling
- Enhanced batch processing capabilities

### Feature Extensions

- Real-time analysis streaming
- Custom detection rule integration
- Advanced visualization capabilities
- Machine learning-enhanced detection

### Platform Support

- Cross-platform die-python builds
- Container deployment options
- Cloud-native analysis services
- Mobile platform considerations
