"""
Model Repositories Package

This package provides access to various model repositories for Intellicrack.
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

# Register repository implementations with the factory
RepositoryFactory.register_repository_type("local", LocalFileRepository)
RepositoryFactory.register_repository_type("openai", OpenAIRepository)
RepositoryFactory.register_repository_type("anthropic", AnthropicRepository)
RepositoryFactory.register_repository_type("openrouter", OpenRouterRepository)
RepositoryFactory.register_repository_type("lmstudio", LMStudioRepository)
RepositoryFactory.register_repository_type("google", GoogleRepository)

__all__ = [
    'ModelRepositoryInterface',
    'ModelInfo',
    'DownloadProgressCallback',
    'APIRepositoryBase',
    'RateLimitConfig',
    'CacheManager',
    'RateLimiter',
    'LocalFileRepository',
    'OpenAIRepository',
    'AnthropicRepository',
    'OpenRouterRepository',
    'LMStudioRepository',
    'GoogleRepository',
    'RepositoryFactory'
]
