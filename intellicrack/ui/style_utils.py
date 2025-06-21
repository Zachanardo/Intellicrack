"""
UI Style Utilities

Common styles and style generators to eliminate duplication across UI components.
"""

def get_progress_bar_style(border_width: int = 1, border_color: str = "#444",
                          background_color: str = "#2a2a2a",
                          chunk_color: str = "#0d7377",
                          border_radius: int = 3) -> str:
    """
    Generate consistent progress bar stylesheet.

    Args:
        border_width: Width of the progress bar border in pixels
        border_color: Color of the border
        background_color: Background color of the progress bar
        chunk_color: Color of the progress bar chunk (filled portion)
        border_radius: Border radius in pixels

    Returns:
        Complete stylesheet string for QProgressBar
    """
    return f"""
        QProgressBar {{
            border: {border_width}px solid {border_color};
            border-radius: {border_radius}px;
            text-align: center;
            background-color: {background_color};
        }}
        QProgressBar::chunk {{
            background-color: {chunk_color};
            border-radius: {border_radius}px;
        }}
    """


def get_default_progress_bar_style() -> str:
    """
    Get the default Intellicrack progress bar style.
    Uses the common theme colors.

    Returns:
        Default progress bar stylesheet
    """
    return get_progress_bar_style()


def get_splash_progress_bar_style() -> str:
    """
    Get the splash screen specific progress bar style.
    Uses green color scheme for splash screen.

    Returns:
        Splash screen progress bar stylesheet
    """
    return get_progress_bar_style(
        border_width=2,
        border_color="grey",
        background_color="#2b2b2b",
        chunk_color="#4CAF50",
        border_radius=5
    )
