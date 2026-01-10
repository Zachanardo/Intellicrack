"""Main application entry point for Intellicrack.

This module bootstraps the application, initializing configuration,
logging, providers, tool bridges, and the GUI.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path


def main() -> int:
    """Run the Intellicrack application.

    Returns:
        Exit code (0 for success, non-zero for failure).
    """
    from intellicrack.core.config import Config
    from intellicrack.core.logging import setup_logging, get_logger

    config_path = Path("config.toml")
    if config_path.exists():
        config = Config.load(config_path)
    else:
        config = Config.default()

    setup_logging(config.log)
    logger = get_logger("main")
    logger.info("Starting Intellicrack")

    try:
        from PyQt6.QtWidgets import QApplication

        from intellicrack.core.orchestrator import Orchestrator
        from intellicrack.core.session import SessionManager
        from intellicrack.core.tools import ToolRegistry
        from intellicrack.credentials.env_loader import CredentialLoader
        from intellicrack.providers.registry import ProviderRegistry
        from intellicrack.ui.app import MainWindow

    except ImportError as e:
        print(f"Required dependencies not available: {e}")
        print("Install required packages with: pixi install")
        return 1

    app = QApplication(sys.argv)
    app.setApplicationName("Intellicrack")
    app.setApplicationVersion("2.0.0")
    app.setStyle("Fusion")

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    try:
        env_path = Path(".env")
        credential_loader = CredentialLoader(env_path)

        provider_registry = ProviderRegistry()
        loop.run_until_complete(_initialize_providers(
            provider_registry,
            credential_loader,
            logger,
        ))

        tool_registry = ToolRegistry(config.tools_directory)
        loop.run_until_complete(tool_registry.initialize())

        session_manager = SessionManager(config.data_directory / "sessions.db")
        loop.run_until_complete(session_manager.initialize())

        orchestrator = Orchestrator(
            provider_registry=provider_registry,
            tool_registry=tool_registry,
            session_manager=session_manager,
        )

        window = MainWindow(config, orchestrator)
        window.show()

        logger.info("Intellicrack UI started")
        exit_code = app.exec()

        loop.run_until_complete(orchestrator.shutdown())
        loop.run_until_complete(session_manager.close())

        logger.info("Intellicrack shutdown complete")
        return exit_code

    except Exception as e:
        logger.exception("Fatal error during startup: %s", e)
        return 1

    finally:
        loop.close()


async def _initialize_providers(
    registry: "ProviderRegistry",
    credentials: "CredentialLoader",
    logger: "Logger",
) -> None:
    """Initialize and connect LLM providers.

    Args:
        registry: Provider registry to populate.
        credentials: Credential loader for API keys.
        logger: Logger instance.
    """
    from intellicrack.core.types import ProviderName
    from intellicrack.providers.anthropic import AnthropicProvider
    from intellicrack.providers.google import GoogleProvider
    from intellicrack.providers.ollama import OllamaProvider
    from intellicrack.providers.openai import OpenAIProvider
    from intellicrack.providers.openrouter import OpenRouterProvider

    providers = [
        (ProviderName.ANTHROPIC, AnthropicProvider),
        (ProviderName.OPENAI, OpenAIProvider),
        (ProviderName.GOOGLE, GoogleProvider),
        (ProviderName.OLLAMA, OllamaProvider),
        (ProviderName.OPENROUTER, OpenRouterProvider),
    ]

    for provider_name, provider_class in providers:
        try:
            provider = provider_class()
            creds = credentials.get_credentials(provider_name)

            if creds:
                await provider.connect(creds)
                logger.info("Connected to %s", provider_name.value)
            else:
                logger.debug("No credentials for %s", provider_name.value)

            registry.register(provider)

        except Exception as e:
            logger.warning("Failed to initialize %s: %s", provider_name.value, e)


if __name__ == "__main__":
    sys.exit(main())
