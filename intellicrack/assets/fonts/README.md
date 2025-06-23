# Intellicrack Fonts Directory

This directory is reserved for custom fonts that may be bundled with Intellicrack.

## Current Font Usage

The application uses the following fonts:
- **UI Fonts**: Segoe UI, Arial, Roboto, System Default
- **Code/Monospace Fonts**: Consolas, Courier New, Source Code Pro, Monospace

## Font Fallback

The application will use system fonts by default. If you experience font-related issues:

1. The application will automatically fall back to available system fonts
2. On Windows: Consolas → Courier New → Monospace
3. On Linux: DejaVu Sans Mono → Liberation Mono → Monospace
4. On macOS: Monaco → Menlo → Courier New → Monospace

## Adding Custom Fonts

To add custom fonts:
1. Place .ttf or .otf files in this directory
2. Update the application to load them using QFontDatabase.addApplicationFont()

Note: Source Code Pro is referenced but not bundled. It will use system installation if available, otherwise fall back to other monospace fonts.