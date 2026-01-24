"""Integration tests for HuggingFaceProvider model listing.

These tests require a valid HUGGINGFACE_API_TOKEN in the .env file.
Tests will be skipped if credentials are not available.

All tests use LIVE API calls - NO hardcoded model names.
"""

from __future__ import annotations

import pytest

from intellicrack.core.types import (
    AuthenticationError,
    ModelInfo,
    ProviderCredentials,
    ProviderError,
    ProviderName,
)
from intellicrack.providers.huggingface import HuggingFaceProvider


@pytest.mark.integration
class TestHuggingFaceModelListing:
    """Tests for HuggingFace model listing functionality.

    These tests validate that HuggingFaceProvider can dynamically fetch
    models from the HuggingFace Hub API. NO hardcoded model names are used.
    """

    @pytest.mark.asyncio
    async def test_list_models_returns_non_empty_list(
        self,
        huggingface_provider: HuggingFaceProvider,
    ) -> None:
        """Test list_models returns at least one model.

        This validates that the API call works and returns actual data.
        HuggingFace Hub has many text-generation models available.
        """
        models = await huggingface_provider.list_models()

        assert isinstance(models, list), f"Expected list, got {type(models)}"
        assert len(models) > 0, "Expected at least one model from HuggingFace API"

    @pytest.mark.asyncio
    async def test_list_models_returns_many_models(
        self,
        huggingface_provider: HuggingFaceProvider,
    ) -> None:
        """Test HuggingFace returns many text-generation models."""
        models = await huggingface_provider.list_models()

        assert len(models) >= 10, f"Expected at least 10 models from HuggingFace, got {len(models)}"

    @pytest.mark.asyncio
    async def test_list_models_returns_model_info_instances(
        self,
        huggingface_provider: HuggingFaceProvider,
    ) -> None:
        """Test all returned items are ModelInfo instances."""
        models = await huggingface_provider.list_models()

        for model in models[:20]:
            assert isinstance(model, ModelInfo), f"Expected ModelInfo, got {type(model)}"

    @pytest.mark.asyncio
    async def test_model_info_has_valid_id(
        self,
        huggingface_provider: HuggingFaceProvider,
    ) -> None:
        """Test all models have non-empty string IDs."""
        models = await huggingface_provider.list_models()

        for model in models[:20]:
            assert isinstance(model.id, str), f"Expected str id, got {type(model.id)}"
            assert len(model.id) > 0, "Model ID should not be empty"

    @pytest.mark.asyncio
    async def test_model_info_has_valid_name(
        self,
        huggingface_provider: HuggingFaceProvider,
    ) -> None:
        """Test all models have non-empty string names."""
        models = await huggingface_provider.list_models()

        for model in models[:20]:
            assert isinstance(model.name, str), f"Expected str name, got {type(model.name)}"
            assert len(model.name) > 0, "Model name should not be empty"

    @pytest.mark.asyncio
    async def test_model_info_has_correct_provider(
        self,
        huggingface_provider: HuggingFaceProvider,
    ) -> None:
        """Test all models report HUGGINGFACE as provider."""
        models = await huggingface_provider.list_models()

        for model in models[:20]:
            assert model.provider == ProviderName.HUGGINGFACE, f"Expected HUGGINGFACE provider, got {model.provider}"

    @pytest.mark.asyncio
    async def test_model_info_has_positive_context_window(
        self,
        huggingface_provider: HuggingFaceProvider,
    ) -> None:
        """Test all models have positive context window size."""
        models = await huggingface_provider.list_models()

        for model in models[:20]:
            assert isinstance(model.context_window, int), f"Expected int context_window, got {type(model.context_window)}"
            assert model.context_window > 0, f"Model {model.id} has invalid context_window: {model.context_window}"

    @pytest.mark.asyncio
    async def test_model_info_has_boolean_capabilities(
        self,
        huggingface_provider: HuggingFaceProvider,
    ) -> None:
        """Test all models have boolean capability flags."""
        models = await huggingface_provider.list_models()

        for model in models[:20]:
            assert isinstance(model.supports_tools, bool), f"Expected bool supports_tools, got {type(model.supports_tools)}"
            assert isinstance(model.supports_vision, bool), f"Expected bool supports_vision, got {type(model.supports_vision)}"
            assert isinstance(model.supports_streaming, bool), f"Expected bool supports_streaming, got {type(model.supports_streaming)}"

    @pytest.mark.asyncio
    async def test_multiple_calls_return_consistent_results(
        self,
        huggingface_provider: HuggingFaceProvider,
    ) -> None:
        """Test list_models returns consistent results across calls."""
        models1 = await huggingface_provider.list_models()
        models2 = await huggingface_provider.list_models()

        ids1 = {m.id for m in models1}
        ids2 = {m.id for m in models2}

        assert ids1 == ids2, "Model IDs should be consistent across calls"

    @pytest.mark.asyncio
    async def test_display_all_available_models(
        self,
        huggingface_provider: HuggingFaceProvider,
    ) -> None:
        """Display all available HuggingFace models for GUI model selection.

        This test fetches and prints the full list of models that would
        be shown to users in the Intellicrack GUI model selection dropdown.
        """
        models = await huggingface_provider.list_models()

        print("\n" + "=" * 80)
        print("HUGGINGFACE INFERENCE API - AVAILABLE MODELS FOR GUI SELECTION")
        print("=" * 80)
        print(f"\nTotal models available: {len(models)}\n")

        print("-" * 80)
        print(f"{'Model ID':<55} {'Context':<10} {'Tools':<6} {'Vision':<6}")
        print("-" * 80)

        for model in models:
            print(
                f"{model.id:<55} "
                f"{model.context_window:<10} "
                f"{'Yes' if model.supports_tools else 'No':<6} "
                f"{'Yes' if model.supports_vision else 'No':<6}"
            )

        print("-" * 80)
        print(f"\nTotal: {len(models)} models available")
        print("=" * 80 + "\n")

        assert len(models) > 0, "Should have at least one model to display"


@pytest.mark.integration
class TestHuggingFaceConnection:
    """Tests for HuggingFace provider connection handling."""

    @pytest.mark.asyncio
    async def test_is_connected_after_connect(
        self,
        huggingface_provider: HuggingFaceProvider,
    ) -> None:
        """Test provider reports connected after successful connection."""
        assert huggingface_provider.is_connected is True

    @pytest.mark.asyncio
    async def test_provider_name_is_huggingface(
        self,
        huggingface_provider: HuggingFaceProvider,
    ) -> None:
        """Test provider name property returns HUGGINGFACE."""
        assert huggingface_provider.name == ProviderName.HUGGINGFACE

    @pytest.mark.asyncio
    async def test_connection_with_empty_key_raises_error(self) -> None:
        """Test connection with empty API token raises AuthenticationError."""
        provider = HuggingFaceProvider()
        empty_creds = ProviderCredentials(api_key="")

        with pytest.raises(AuthenticationError):
            await provider.connect(empty_creds)

    @pytest.mark.asyncio
    async def test_list_models_without_connection_raises_error(self) -> None:
        """Test list_models raises error when not connected."""
        provider = HuggingFaceProvider()

        with pytest.raises(ProviderError):
            await provider.list_models()

    @pytest.mark.asyncio
    async def test_disconnect_clears_connection_state(
        self,
        credential_loader,
        has_huggingface_key: bool,
    ) -> None:
        """Test disconnect properly clears connection state."""
        if not has_huggingface_key:
            pytest.skip("HUGGINGFACE_API_TOKEN not configured")

        provider = HuggingFaceProvider()
        credentials = credential_loader.get_credentials(ProviderName.HUGGINGFACE)
        assert credentials is not None

        await provider.connect(credentials)
        assert provider.is_connected is True

        await provider.disconnect()
        assert provider.is_connected is False


@pytest.mark.integration
class TestHuggingFaceContextWindowEstimation:
    """Tests for context window size estimation."""

    def test_known_model_context_windows(self) -> None:
        """Test context window estimation for known models."""
        provider = HuggingFaceProvider()

        assert provider._estimate_context_window("meta-llama/Llama-3.3-70B-Instruct") == 128000
        assert provider._estimate_context_window("Qwen/Qwen2.5-72B-Instruct") == 131072
        assert provider._estimate_context_window("mistralai/Mistral-7B-Instruct-v0.3") == 32768

    def test_unknown_model_default_context_window(self) -> None:
        """Test unknown models get default context window."""
        provider = HuggingFaceProvider()

        assert provider._estimate_context_window("unknown/model-name") == 4096


@pytest.mark.integration
class TestHuggingFaceToolSupport:
    """Tests for tool calling support estimation."""

    def test_llama_models_support_tools(self) -> None:
        """Test Llama models are marked as supporting tools."""
        provider = HuggingFaceProvider()

        assert provider._estimate_tool_support("meta-llama/Llama-3.3-70B-Instruct")
        assert provider._estimate_tool_support("meta-llama/Llama-3.1-8B-Instruct")

    def test_mistral_models_support_tools(self) -> None:
        """Test Mistral models are marked as supporting tools."""
        provider = HuggingFaceProvider()

        assert provider._estimate_tool_support("mistralai/Mistral-7B-Instruct-v0.3")
        assert provider._estimate_tool_support("mistralai/Mixtral-8x7B-Instruct-v0.1")

    def test_falcon_models_no_tool_support(self) -> None:
        """Test Falcon models are not marked for tool support."""
        provider = HuggingFaceProvider()

        assert not provider._estimate_tool_support("tiiuae/falcon-7b-instruct")


@pytest.mark.integration
class TestHuggingFaceVisionSupport:
    """Tests for vision support estimation."""

    def test_vision_models_detected(self) -> None:
        """Test vision models are correctly identified."""
        provider = HuggingFaceProvider()

        assert provider._estimate_vision_support("llava-hf/llava-1.5-7b-hf")
        assert provider._estimate_vision_support("Qwen/Qwen-VL-Chat")
        assert provider._estimate_vision_support("microsoft/Florence-2-vision")

    def test_text_only_models_no_vision(self) -> None:
        """Test text-only models are not marked for vision."""
        provider = HuggingFaceProvider()

        assert not provider._estimate_vision_support("meta-llama/Llama-3.3-70B-Instruct")
        assert not provider._estimate_vision_support("mistralai/Mistral-7B-Instruct-v0.3")
