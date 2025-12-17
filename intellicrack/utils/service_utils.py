"""Lightweight service utilities to avoid circular imports.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import logging

from intellicrack.core.exceptions import ConfigurationError


logger = logging.getLogger(__name__)


def get_service_url(service_name: str, fallback: str = None) -> str:
    """Get URL for a service from configuration.

    Args:
        service_name: Name of the service
        fallback: Optional fallback URL to use if service is not configured

    Returns:
        Service URL from configuration or fallback

    Raises:
        ConfigurationError: If service URL is not configured and no fallback provided

    """
    # Import here to avoid circular imports
    try:
        from intellicrack.core.config_manager import get_config

        config = get_config()
    except ImportError as e:
        logger.warning("Could not import config manager: %s", e, exc_info=True)
        error_msg = f"Cannot access configuration for service '{service_name}'"
        logger.error(error_msg)
        raise ConfigurationError(
            error_msg,
            service_name=service_name,
        ) from e

    url = config.get(f"service_urls.{service_name}")
    if not url:
        if fallback:
            url = fallback
            logger.debug("Using fallback URL for service '%s': %s", service_name, fallback)
        else:
            error_msg = f"Service '{service_name}' URL not configured. Please set 'service_urls.{service_name}' in configuration."
            logger.error(error_msg)
            raise ConfigurationError(
                error_msg,
                service_name=service_name,
                config_key=f"service_urls.{service_name}",
            )

    # Validate URL format
    if not url.startswith(("http://", "https://", "ws://", "wss://", "tcp://", "udp://")):
        error_msg = (
            f"Invalid URL format for service '{service_name}': {url}. "
            f"URL must start with a valid protocol (http://, https://, ws://, wss://, tcp://, udp://)"
        )
        logger.error(error_msg)
        raise ConfigurationError(
            error_msg,
            service_name=service_name,
            config_key=f"service_urls.{service_name}",
        )

    return url
