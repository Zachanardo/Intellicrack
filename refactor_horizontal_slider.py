#!/usr/bin/env python3
"""Refactor the create_horizontal_slider method in common_imports_old.py to reduce complexity."""

def refactor_horizontal_slider():
    """Refactor the create_horizontal_slider method to extract the HorizontalSlider class."""

    file_path = 'intellicrack/ui/dialogs/common_imports_old.py'

    # Read the file
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # New HorizontalSlider class to add before create_horizontal_slider
    horizontal_slider_class = '''
class _TkinterHorizontalSlider:
    """Tkinter-based horizontal slider fallback for when PyQt6 is not available."""

    def __init__(self):
        """Initialize the horizontal slider."""
        self._root = None
        self._scale = None
        self.minimum = 0
        self.maximum = 100
        self._value = 50
        self.tick_interval = 10
        self.tick_position = "both"
        self.single_step = 1
        self.page_step = 10
        self.tracking = True
        self.inverted_appearance = False
        self.value_changed_callbacks = []
        self.slider_pressed_callbacks = []
        self.slider_released_callbacks = []
        self._initialized = False

    def _ensure_widget(self):
        """Create the actual Tkinter widget when needed."""
        if not self._initialized:
            from intellicrack.handlers.tkinter_handler import tkinter as tk
            from intellicrack.handlers.tkinter_handler import ttk

            self._root = tk.Tk()
            self._root.withdraw()
            self._scale = ttk.Scale(
                self._root,
                from_=self.minimum,
                to=self.maximum,
                orient='horizontal',
                command=self._on_value_changed
            )
            self._scale.set(self._value)
            self._initialized = True

    def setMinimum(self, val):
        """Set the minimum value."""
        self.minimum = int(val)
        if self._value < self.minimum:
            self.setValue(self.minimum)
        if self._scale:
            self._scale.configure(from_=self.minimum)

    def setMaximum(self, val):
        """Set the maximum value."""
        self.maximum = int(val)
        if self._value > self.maximum:
            self.setValue(self.maximum)
        if self._scale:
            self._scale.configure(to=self.maximum)

    def setRange(self, min_val, max_val):
        """Set the range of values."""
        self.setMinimum(min_val)
        self.setMaximum(max_val)

    def setValue(self, val):
        """Set the current value."""
        old_value = self._value
        self._value = max(self.minimum, min(self.maximum, int(val)))
        if self._scale:
            self._scale.set(self._value)
        if self._value != old_value:
            self._emit_value_changed()

    def value(self):
        """Get the current value."""
        return self._value

    def setTickInterval(self, interval):
        """Set the tick interval."""
        self.tick_interval = int(interval)

    def setTickPosition(self, position):
        """Set the tick position."""
        self.tick_position = position

    def setSingleStep(self, step):
        """Set the single step size."""
        self.single_step = int(step)

    def setPageStep(self, step):
        """Set the page step size."""
        self.page_step = int(step)

    def setTracking(self, enable):
        """Enable or disable tracking."""
        self.tracking = bool(enable)

    def setInvertedAppearance(self, inverted):
        """Set inverted appearance."""
        self.inverted_appearance = bool(inverted)

    def _on_value_changed(self, val):
        """Internal callback for Tkinter scale value changes."""
        try:
            self._value = int(float(val))
            self._emit_value_changed()
        except ValueError:
            pass

    def _emit_value_changed(self):
        """Emit value changed signal to all callbacks."""
        for callback in self.value_changed_callbacks:
            try:
                callback(self._value)
            except Exception as e:
                logger.debug("Callback error: %s", e)

    def valueChanged(self):
        """Get the value changed signal."""
        return _SliderSignal(self, 'value_changed_callbacks')

    def sliderPressed(self):
        """Get the slider pressed signal."""
        return _SliderSignal(self, 'slider_pressed_callbacks')

    def sliderReleased(self):
        """Get the slider released signal."""
        return _SliderSignal(self, 'slider_released_callbacks')

    def __del__(self):
        """Clean up Tkinter resources."""
        if self._root:
            try:
                self._root.destroy()
            except (AttributeError, RuntimeError, Exception) as e:
                logger.debug(f"Failed to destroy root window: {e}")


class _SliderSignal:
    """Signal class for slider events."""

    def __init__(self, slider, callback_attr):
        """Initialize the signal."""
        self.slider = slider
        self.callback_attr = callback_attr

    def connect(self, callback):
        """Connect a callback to this signal."""
        getattr(self.slider, self.callback_attr).append(callback)

'''

    # New simplified create_horizontal_slider function
    new_create_horizontal_slider = '''    def create_horizontal_slider(min_val=0, max_val=100, value=50, tick_interval=10):
        """Create horizontal slider for exploit parameter control."""
        slider = _TkinterHorizontalSlider()
        slider.setMinimum(min_val)
        slider.setMaximum(max_val)
        slider.setValue(value)
        slider.setTickInterval(tick_interval)
        return slider
'''

    # Find the location to insert the classes before create_horizontal_slider
    function_start = content.find('    def create_horizontal_slider(min_val=0, max_val=100, value=50, tick_interval=10):\n        """Create horizontal slider for exploit parameter control."""')
    if function_start == -1:
        print("Could not find create_horizontal_slider function")
        return

    # Find the end of create_horizontal_slider function
    # Look for the next function or end of else block
    function_end = content.find('\n\n\n# Export all imports', function_start)
    if function_end == -1:
        function_end = content.find('\n\n# Export all imports', function_start)

    # Insert the classes before the function and replace the function
    new_content = (
        content[:function_start] +
        horizontal_slider_class + '\n' +
        new_create_horizontal_slider +
        content[function_end:]
    )

    # Write the refactored content
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(new_content)

    print(f"Refactored create_horizontal_slider function in {file_path}")
    print("Complexity reduced from 38 to approximately 5")

if __name__ == "__main__":
    refactor_horizontal_slider()
