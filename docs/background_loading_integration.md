# Background Model Loading Integration Guide

This guide explains how to use the BackgroundModelLoader with QueuedProgressCallback for asynchronous model loading with progress tracking in Intellicrack.

## Overview

The BackgroundModelLoader provides:
- Asynchronous model loading in background threads
- Priority-based task queuing
- Progress tracking with callbacks
- Cancellation support
- Loading statistics
- Integration with the LLM Manager

## Key Components

### 1. QueuedProgressCallback

The `QueuedProgressCallback` class (line 88 in `background_loader.py`) provides a queue-based mechanism for handling progress updates in GUI applications:

```python
from intellicrack.ai.background_loader import QueuedProgressCallback

# Create callback
callback = QueuedProgressCallback()

# Get updates (non-blocking)
progress_updates = callback.get_progress_updates()  # Line 104
completion_updates = callback.get_completion_updates()  # Line 114
```

### 2. LLMManager Integration

The LLMManager now includes background loading methods:

```python
from intellicrack.ai.llm_backends import get_llm_manager

llm_manager = get_llm_manager()

# Add progress callback
llm_manager.add_progress_callback(callback)

# Load model in background
task = llm_manager.load_model_in_background(
    llm_id="my_model",
    config=config,
    priority=5
)

# Get progress
progress = llm_manager.get_loading_progress("my_model")

# Cancel loading
llm_manager.cancel_loading("my_model")

# Get all tasks
tasks = llm_manager.get_all_loading_tasks()

# Get statistics
stats = llm_manager.get_loading_statistics()
```

### 3. Progress Widget

The `ModelLoadingProgressWidget` provides a complete UI for monitoring loading progress:

```python
from intellicrack.ui.widgets.model_loading_progress_widget import ModelLoadingProgressWidget

# Create widget
progress_widget = ModelLoadingProgressWidget()

# Connect to model loaded signal
progress_widget.model_loaded.connect(on_model_loaded)

# Widget automatically updates with progress
```

## Usage Examples

### Basic Background Loading

```python
from intellicrack.ai.llm_config_manager import LLMConfig, LLMProvider
from intellicrack.ai.llm_backends import get_llm_manager

# Get manager
llm_manager = get_llm_manager()

# Create config
config = LLMConfig(
    provider=LLMProvider.OLLAMA,
    model_name="llama2",
    api_url="http://localhost:11434"
)

# Load in background
task = llm_manager.load_model_in_background(
    llm_id="ollama_llama2",
    config=config,
    priority=5  # Higher priority loads first
)
```

### Progress Monitoring in GUI

```python
from PyQt5.QtCore import QTimer
from intellicrack.ai.background_loader import QueuedProgressCallback

class MyWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.callback = QueuedProgressCallback()
        self.llm_manager = get_llm_manager()
        
        # Register callback
        self.llm_manager.add_progress_callback(self.callback)
        
        # Setup timer for updates
        self.timer = QTimer()
        self.timer.timeout.connect(self.process_updates)
        self.timer.start(100)  # Update every 100ms
        
    def process_updates(self):
        # Get progress updates
        for progress in self.callback.get_progress_updates():
            self.update_progress_bar(progress)
            
        # Get completion updates
        for model_id, success, error in self.callback.get_completion_updates():
            if success:
                self.on_model_loaded(model_id)
            else:
                self.on_load_failed(model_id, error)
```

### Complete Dialog Example

```python
from intellicrack.ui.dialogs.model_loading_dialog import ModelLoadingDialog

# Create and show dialog
dialog = ModelLoadingDialog(parent_widget)
dialog.model_loaded.connect(handle_model_loaded)
dialog.exec_()
```

## Integration Points

### 1. AI Script Generation

When generating scripts, models can be loaded on-demand:

```python
# In script generator
if not llm_manager.is_model_loaded(model_id):
    task = llm_manager.load_model_in_background(model_id, config)
    # Show progress while loading
```

### 2. Protection Analysis

For ML-based protection detection:

```python
# Load protection detection model in background
ml_config = LLMConfig(
    provider=LLMProvider.PYTORCH,
    model_path="models/protection_detector.pth"
)

task = llm_manager.load_model_in_background(
    "protection_ml_model",
    ml_config,
    priority=10  # High priority
)
```

### 3. Vulnerability Research

Load specialized models for vulnerability analysis:

```python
# Load vulnerability analysis model
vuln_config = LLMConfig(
    provider=LLMProvider.HUGGINGFACE_LOCAL,
    model_path="models/vuln_analyzer"
)

task = llm_manager.load_model_in_background(
    "vuln_analyzer",
    vuln_config,
    priority=8
)
```

## Advanced Features

### Priority Management

Models are loaded based on priority (higher = sooner):
- 10: Critical system models
- 8-9: Important user-requested models
- 5-7: Standard models
- 1-4: Background/optional models

### Cancellation

```python
# Cancel specific model
llm_manager.cancel_loading("model_id")

# Cancel all
for model_id in llm_manager.get_all_loading_tasks():
    llm_manager.cancel_loading(model_id)
```

### Statistics

```python
stats = llm_manager.get_loading_statistics()
print(f"Success rate: {stats['success_rate']:.1%}")
print(f"Active workers: {stats['active_workers']}")
```

## Best Practices

1. **Use Priorities**: Assign appropriate priorities based on urgency
2. **Monitor Progress**: Always provide visual feedback for loading
3. **Handle Failures**: Implement retry logic for failed loads
4. **Cleanup**: Remove progress callbacks when done
5. **Resource Management**: Limit concurrent loads based on system resources

## Running the Example

To see the background loading in action:

```bash
cd examples
python background_loading_example.py
```

This demonstrates:
- Loading multiple models concurrently
- Progress tracking with visual feedback
- Priority-based loading
- Cancellation support
- Statistics monitoring

## Troubleshooting

### Models Not Loading
- Check API endpoints are accessible
- Verify API keys are configured
- Check system resources (RAM, disk space)

### Progress Not Updating
- Ensure callbacks are registered
- Check update timer is running
- Verify queue processing is active

### High Memory Usage
- Limit concurrent loads: `BackgroundModelLoader(max_concurrent_loads=1)`
- Unload unused models: `llm_manager.unload_llm("model_id")`
- Monitor with: `llm_manager.get_memory_usage()`