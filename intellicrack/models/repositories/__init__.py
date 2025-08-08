"""This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

from .anthropic_repository import AnthropicRepository
from .base import APIRepositoryBase, CacheManager, RateLimitConfig, RateLimiter
from .factory import RepositoryFactory
from .google_repository import GoogleRepository
from .interface import DownloadProgressCallback, ModelInfo, ModelRepositoryInterface
from .lmstudio_repository import LMStudioRepository
from .local_repository import LocalFileRepository
from .openai_repository import OpenAIRepository
from .openrouter_repository import OpenRouterRepository

"""
Model Repositories Package

This package provides access to various model repositories for Intellicrack.
"""

# Register repository implementations with the factory
RepositoryFactory.register_repository_type("local", LocalFileRepository)
RepositoryFactory.register_repository_type("openai", OpenAIRepository)
RepositoryFactory.register_repository_type("anthropic", AnthropicRepository)
RepositoryFactory.register_repository_type("openrouter", OpenRouterRepository)
RepositoryFactory.register_repository_type("lmstudio", LMStudioRepository)
RepositoryFactory.register_repository_type("google", GoogleRepository)

__all__ = [
    "APIRepositoryBase",
    "AnthropicRepository",
    "CacheManager",
    "DownloadProgressCallback",
    "GoogleRepository",
    "LMStudioRepository",
    "LocalFileRepository",
    "ModelInfo",
    "ModelRepositoryInterface",
    "OpenAIRepository",
    "OpenRouterRepository",
    "RateLimitConfig",
    "RateLimiter",
    "RepositoryFactory",
]
