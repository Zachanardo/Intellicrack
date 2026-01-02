"""Production tests for model_format_converter.py - Real model conversion validation.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

from __future__ import annotations

import contextlib
import sys
import tempfile
from pathlib import Path
from collections.abc import Generator, Iterator
from typing import TYPE_CHECKING, Any, Protocol

import numpy as np
from numpy.typing import NDArray
import pytest

from intellicrack.ai.model_format_converter import ModelFormatConverter


class SafeOpenContextProtocol(Protocol):
    """Protocol for safe_open context manager."""

    def keys(self) -> list[str]:
        """Get tensor keys."""
        ...

    def get_tensor(self, name: str) -> Any:
        """Get tensor by name."""
        ...


HAS_TORCH = False
HAS_ONNX = False
HAS_SAFETENSORS = False

_safe_open_func: Any = None

if TYPE_CHECKING:
    import torch
    import onnx
    import onnxruntime as ort
    from safetensors.torch import save_file
else:
    torch = None
    onnx = None
    ort = None
    save_file = None

    try:
        import torch
        HAS_TORCH = True
    except ImportError:
        pass

    try:
        import onnx
        import onnxruntime as ort
        HAS_ONNX = True
    except ImportError:
        pass

    try:
        from safetensors.torch import save_file
        from safetensors import safe_open as _safe_open
        _safe_open_func = _safe_open
        HAS_SAFETENSORS = True
    except ImportError:
        pass


@contextlib.contextmanager
def typed_safe_open(path: str, framework: str = "pt") -> Iterator[SafeOpenContextProtocol]:
    """Type-safe wrapper for safetensors safe_open.

    Args:
        path: Path to safetensors file.
        framework: Framework type (pt, np, etc).

    Yields:
        Context manager with typed interface.
    """
    if _safe_open_func is None:
        raise RuntimeError("safetensors not available")
    ctx = _safe_open_func(path, framework=framework)
    try:
        yield ctx
    finally:
        pass


class TestModelFormatConverterInitialization:
    """Production tests for ModelFormatConverter initialization."""

    def test_converter_initializes_successfully(self) -> None:
        """ModelFormatConverter initializes with valid configuration."""
        converter: ModelFormatConverter = ModelFormatConverter()

        assert converter is not None, "Converter must initialize"
        assert hasattr(converter, "supported_conversions"), "Must have supported conversions"
        assert isinstance(converter.supported_conversions, dict), "Conversions must be dict"

    def test_supported_conversions_based_on_available_libraries(self) -> None:
        """Supported conversions reflect actually installed libraries."""
        converter: ModelFormatConverter = ModelFormatConverter()
        conversions: dict[str, list[str]] = converter.supported_conversions

        if HAS_ONNX:
            assert "onnx" in conversions.get("pytorch", []), "Should support PyTorch -> ONNX"

        if HAS_SAFETENSORS:
            assert "safetensors" in conversions.get("pytorch", []), "Should support PyTorch -> SafeTensors"
            assert "pytorch" in conversions.get("safetensors", []), "Should support SafeTensors -> PyTorch"

    def test_gpu_info_captured_when_available(self) -> None:
        """GPU information is captured if GPU is available."""
        converter: ModelFormatConverter = ModelFormatConverter()

        if converter.gpu_info:
            assert isinstance(converter.gpu_info, dict), "GPU info must be dict"
            assert str(converter.gpu_info) != "", "GPU info must have content"


class TestFormatDetection:
    """Production tests for model format detection."""

    @pytest.fixture
    def converter(self) -> ModelFormatConverter:
        """Create converter for testing."""
        return ModelFormatConverter()

    @pytest.fixture
    def temp_dir(self) -> Generator[Path, None, None]:
        """Create temporary directory."""
        with tempfile.TemporaryDirectory(prefix="model_test_") as tmp:
            yield Path(tmp)

    @pytest.mark.skipif(not HAS_TORCH, reason="PyTorch not available")
    def test_detect_pytorch_file_by_extension(self, converter: ModelFormatConverter, temp_dir: Path) -> None:
        """Format detection identifies PyTorch files by extension."""
        test_file: Path = temp_dir / "model.pt"
        torch.save({"layer": torch.randn(10, 10)}, str(test_file))

        detected: str | None = converter._detect_format(test_file)
        assert detected == "pytorch", "Must detect .pt as PyTorch format"

    @pytest.mark.skipif(not HAS_TORCH, reason="PyTorch not available")
    def test_detect_pytorch_pth_extension(self, converter: ModelFormatConverter, temp_dir: Path) -> None:
        """Format detection identifies .pth as PyTorch."""
        test_file: Path = temp_dir / "model.pth"
        torch.save({"layer": torch.randn(10, 10)}, str(test_file))

        detected: str | None = converter._detect_format(test_file)
        assert detected == "pytorch", "Must detect .pth as PyTorch format"

    @pytest.mark.skipif(not HAS_ONNX, reason="ONNX not available")
    def test_detect_onnx_file_by_extension(self, converter: ModelFormatConverter, temp_dir: Path) -> None:
        """Format detection identifies ONNX files."""
        test_file: Path = temp_dir / "model.onnx"

        input_tensor = onnx.helper.make_tensor_value_info("input", onnx.TensorProto.FLOAT, [1, 3, 224, 224])
        output_tensor = onnx.helper.make_tensor_value_info("output", onnx.TensorProto.FLOAT, [1, 1000])

        node_def = onnx.helper.make_node("Identity", ["input"], ["output"])
        graph_def = onnx.helper.make_graph([node_def], "test_model", [input_tensor], [output_tensor])
        model_def = onnx.helper.make_model(graph_def, producer_name="test")

        onnx.save(model_def, str(test_file))

        detected: str | None = converter._detect_format(test_file)
        assert detected == "onnx", "Must detect .onnx format"

    @pytest.mark.skipif(not HAS_SAFETENSORS, reason="SafeTensors not available")
    def test_detect_safetensors_file(self, converter: ModelFormatConverter, temp_dir: Path) -> None:
        """Format detection identifies SafeTensors files."""
        test_file: Path = temp_dir / "model.safetensors"

        tensors: dict[str, Any] = {"weight": torch.randn(10, 10)}
        save_file(tensors, str(test_file))

        detected: str | None = converter._detect_format(test_file)
        assert detected == "safetensors", "Must detect .safetensors format"

    @pytest.mark.skipif(not HAS_TORCH, reason="PyTorch not available")
    def test_detect_pytorch_directory_with_bin_file(self, converter: ModelFormatConverter, temp_dir: Path) -> None:
        """Format detection identifies PyTorch model directories."""
        model_dir: Path = temp_dir / "model"
        model_dir.mkdir()

        model_file: Path = model_dir / "pytorch_model.bin"
        torch.save({"layer": torch.randn(10, 10)}, str(model_file))

        detected: str | None = converter._detect_format(model_dir)
        assert detected == "pytorch", "Must detect directory with pytorch_model.bin"

    def test_detect_format_returns_none_for_unknown(self, converter: ModelFormatConverter, temp_dir: Path) -> None:
        """Format detection returns None for unknown formats."""
        test_file: Path = temp_dir / "unknown.xyz"
        test_file.write_text("random content")

        detected: str | None = converter._detect_format(test_file)
        assert detected is None, "Must return None for unknown format"


@pytest.mark.skipif(not (HAS_TORCH and HAS_ONNX), reason="PyTorch and ONNX required")
class TestPyTorchToONNXConversion:
    """Production tests for PyTorch to ONNX conversion."""

    @pytest.fixture
    def converter(self) -> ModelFormatConverter:
        """Create converter for testing."""
        return ModelFormatConverter()

    @pytest.fixture
    def temp_dir(self) -> Generator[Path, None, None]:
        """Create temporary directory."""
        with tempfile.TemporaryDirectory(prefix="conversion_test_") as tmp:
            yield Path(tmp)

    def test_convert_simple_pytorch_model_to_onnx(self, converter: ModelFormatConverter, temp_dir: Path) -> None:
        """Converts simple PyTorch model to valid ONNX format."""

        class SimpleModel(torch.nn.Module):
            def __init__(self) -> None:
                super().__init__()
                self.linear: torch.nn.Linear = torch.nn.Linear(10, 5)

            def forward(self, x: torch.Tensor) -> torch.Tensor:
                result: torch.Tensor = self.linear(x)
                return result

        model = SimpleModel()
        model.eval()

        source_path: Path = temp_dir / "simple_model.pt"
        torch.save(model, str(source_path))

        output_path: Path = temp_dir / "simple_model.onnx"

        result: Path | None = converter._convert_pytorch_to_onnx(
            source_path,
            output_path,
            input_shape=(1, 10),
        )

        assert result is not None, "Conversion must succeed"
        assert result.exists(), "ONNX file must be created"
        assert result == output_path, "Output path must match"

        onnx_model = onnx.load(str(result))
        onnx.checker.check_model(onnx_model)

    def test_onnx_conversion_creates_runnable_model(self, converter: ModelFormatConverter, temp_dir: Path) -> None:
        """Converted ONNX model is executable with ONNX Runtime."""

        class TestModel(torch.nn.Module):
            def __init__(self) -> None:
                super().__init__()
                self.fc: torch.nn.Linear = torch.nn.Linear(20, 10)

            def forward(self, x: torch.Tensor) -> torch.Tensor:
                result: torch.Tensor = self.fc(x)
                return result

        model = TestModel()
        model.eval()

        source_path: Path = temp_dir / "test_model.pt"
        torch.save(model, str(source_path))

        output_path: Path = temp_dir / "test_model.onnx"

        result: Path | None = converter._convert_pytorch_to_onnx(
            source_path,
            output_path,
            input_shape=(1, 20),
        )

        assert result is not None, "Conversion must succeed"

        session = ort.InferenceSession(str(result))

        test_input: NDArray[np.floating[Any]] = np.random.randn(1, 20).astype(np.float32)
        outputs = session.run(None, {"input_ids": test_input})

        assert outputs is not None, "Model must produce output"
        assert len(outputs) > 0, "Must have at least one output"
        assert outputs[0].shape == (1, 10), "Output shape must match model"

    def test_pytorch_to_onnx_with_dynamic_axes(self, converter: ModelFormatConverter, temp_dir: Path) -> None:
        """ONNX conversion supports dynamic batch sizes."""

        class DynamicModel(torch.nn.Module):
            def __init__(self) -> None:
                super().__init__()
                self.conv: torch.nn.Conv2d = torch.nn.Conv2d(3, 16, 3, padding=1)

            def forward(self, x: torch.Tensor) -> torch.Tensor:
                result: torch.Tensor = self.conv(x)
                return result

        model = DynamicModel()
        model.eval()

        source_path: Path = temp_dir / "dynamic_model.pt"
        torch.save(model, str(source_path))

        output_path: Path = temp_dir / "dynamic_model.onnx"

        result: Path | None = converter._convert_pytorch_to_onnx(
            source_path,
            output_path,
            input_shape=(2, 3, 64, 64),
            dynamic_axes={"input_ids": {0: "batch"}, "output": {0: "batch"}},
        )

        assert result is not None, "Conversion must succeed"

        session = ort.InferenceSession(str(result))

        for batch_size in [1, 2, 4]:
            test_input: NDArray[np.floating[Any]] = np.random.randn(batch_size, 3, 64, 64).astype(np.float32)
            outputs = session.run(None, {"input_ids": test_input})
            assert outputs[0].shape[0] == batch_size, f"Must handle batch size {batch_size}"

    def test_pytorch_to_onnx_handles_invalid_input_shape(self, converter: ModelFormatConverter, temp_dir: Path) -> None:
        """Conversion fails gracefully with missing input_shape."""

        class Model(torch.nn.Module):
            def forward(self, x: torch.Tensor) -> torch.Tensor:
                result: torch.Tensor = x * 2
                return result

        model = Model()
        source_path: Path = temp_dir / "model.pt"
        torch.save(model, str(source_path))

        output_path: Path = temp_dir / "output.onnx"

        result: Path | None = converter._convert_pytorch_to_onnx(
            source_path,
            output_path,
        )

        assert result is None, "Must fail without input_shape"


@pytest.mark.skipif(not (HAS_TORCH and HAS_SAFETENSORS), reason="PyTorch and SafeTensors required")
class TestPyTorchToSafeTensorsConversion:
    """Production tests for PyTorch to SafeTensors conversion."""

    @pytest.fixture
    def converter(self) -> ModelFormatConverter:
        """Create converter for testing."""
        return ModelFormatConverter()

    @pytest.fixture
    def temp_dir(self) -> Generator[Path, None, None]:
        """Create temporary directory."""
        with tempfile.TemporaryDirectory(prefix="safetensors_test_") as tmp:
            yield Path(tmp)

    def test_convert_pytorch_state_dict_to_safetensors(self, converter: ModelFormatConverter, temp_dir: Path) -> None:
        """Converts PyTorch state dict to SafeTensors format."""
        state_dict: dict[str, torch.Tensor] = {
            "layer1.weight": torch.randn(100, 50),
            "layer1.bias": torch.randn(100),
            "layer2.weight": torch.randn(50, 25),
            "layer2.bias": torch.randn(50),
        }

        source_path: Path = temp_dir / "model.pt"
        torch.save(state_dict, str(source_path))

        output_path: Path = temp_dir / "model.safetensors"

        result: Path | None = converter._convert_pytorch_to_safetensors(
            source_path,
            output_path,
        )

        assert result is not None, "Conversion must succeed"
        assert result.exists(), "SafeTensors file must be created"
        assert result.suffix == ".safetensors", "Must have correct extension"

        with typed_safe_open(str(result), framework="pt") as f:
            loaded_keys = list(f.keys())
            assert len(loaded_keys) == 4, "All tensors must be saved"
            assert "layer1.weight" in loaded_keys, "Must preserve tensor names"

            weight = f.get_tensor("layer1.weight")
            assert weight.shape == (100, 50), "Must preserve tensor shapes"

    def test_safetensors_preserves_tensor_values(self, converter: ModelFormatConverter, temp_dir: Path) -> None:
        """SafeTensors conversion preserves exact tensor values."""
        original_tensor: torch.Tensor = torch.randn(256, 128)
        state_dict: dict[str, torch.Tensor] = {"test_tensor": original_tensor}

        source_path: Path = temp_dir / "original.pt"
        torch.save(state_dict, str(source_path))

        output_path: Path = temp_dir / "converted.safetensors"

        result: Path | None = converter._convert_pytorch_to_safetensors(
            source_path,
            output_path,
        )

        assert result is not None, "Conversion must succeed"

        with typed_safe_open(str(result), framework="pt") as f:
            loaded_tensor: torch.Tensor = f.get_tensor("test_tensor")

            assert torch.allclose(loaded_tensor, original_tensor, rtol=1e-5), "Values must match exactly"

    def test_safetensors_conversion_adds_extension(self, converter: ModelFormatConverter, temp_dir: Path) -> None:
        """Conversion adds .safetensors extension if missing."""
        state_dict: dict[str, torch.Tensor] = {"weight": torch.randn(10, 10)}

        source_path: Path = temp_dir / "model.pt"
        torch.save(state_dict, str(source_path))

        output_path: Path = temp_dir / "model_output"

        result: Path | None = converter._convert_pytorch_to_safetensors(
            source_path,
            output_path,
        )

        assert result is not None, "Conversion must succeed"
        assert result.suffix == ".safetensors", "Must add .safetensors extension"

    def test_safetensors_conversion_from_directory(self, converter: ModelFormatConverter, temp_dir: Path) -> None:
        """Conversion handles PyTorch model directories."""
        model_dir: Path = temp_dir / "model"
        model_dir.mkdir()

        state_dict1: dict[str, torch.Tensor] = {"part1": torch.randn(50, 25)}
        state_dict2: dict[str, torch.Tensor] = {"part2": torch.randn(25, 10)}

        torch.save(state_dict1, str(model_dir / "model_part1.bin"))
        torch.save(state_dict2, str(model_dir / "model_part2.bin"))

        output_path: Path = temp_dir / "combined.safetensors"

        result: Path | None = converter._convert_pytorch_to_safetensors(
            model_dir,
            output_path,
        )

        assert result is not None, "Conversion must succeed"

        with typed_safe_open(str(result), framework="pt") as f:
            keys = list(f.keys())
            assert "part1" in keys, "Must load from first file"
            assert "part2" in keys, "Must load from second file"


@pytest.mark.skipif(not (HAS_TORCH and HAS_SAFETENSORS), reason="PyTorch and SafeTensors required")
class TestSafeTensorsToPyTorchConversion:
    """Production tests for SafeTensors to PyTorch conversion."""

    @pytest.fixture
    def converter(self) -> ModelFormatConverter:
        """Create converter for testing."""
        return ModelFormatConverter()

    @pytest.fixture
    def temp_dir(self) -> Generator[Path, None, None]:
        """Create temporary directory."""
        with tempfile.TemporaryDirectory(prefix="st_to_pt_") as tmp:
            yield Path(tmp)

    def test_convert_safetensors_to_pytorch(self, converter: ModelFormatConverter, temp_dir: Path) -> None:
        """Converts SafeTensors back to PyTorch format."""
        tensors: dict[str, torch.Tensor] = {
            "embedding.weight": torch.randn(1000, 512),
            "classifier.weight": torch.randn(10, 512),
            "classifier.bias": torch.randn(10),
        }

        source_path: Path = temp_dir / "model.safetensors"
        save_file(tensors, str(source_path))

        output_path: Path = temp_dir / "model.pt"

        result: Path | None = converter._convert_safetensors_to_pytorch(
            source_path,
            output_path,
        )

        assert result is not None, "Conversion must succeed"
        assert result.exists(), "PyTorch file must be created"

        loaded: dict[str, torch.Tensor] = torch.load(str(result))

        assert len(loaded) == 3, "All tensors must be loaded"
        assert "embedding.weight" in loaded, "Must have embedding weight"
        assert loaded["embedding.weight"].shape == (1000, 512), "Shape must be preserved"

    def test_safetensors_to_pytorch_preserves_values(self, converter: ModelFormatConverter, temp_dir: Path) -> None:
        """Conversion preserves exact tensor values."""
        original: torch.Tensor = torch.randn(128, 256)
        tensors: dict[str, torch.Tensor] = {"data": original}

        source_path: Path = temp_dir / "source.safetensors"
        save_file(tensors, str(source_path))

        output_path: Path = temp_dir / "output.pt"

        result: Path | None = converter._convert_safetensors_to_pytorch(
            source_path,
            output_path,
        )

        assert result is not None, "Conversion must succeed"

        loaded: dict[str, torch.Tensor] = torch.load(str(result))
        assert torch.allclose(loaded["data"], original, rtol=1e-5), "Values must match"

    def test_safetensors_to_pytorch_adds_pt_extension(self, converter: ModelFormatConverter, temp_dir: Path) -> None:
        """Conversion adds .pt extension if needed."""
        tensors: dict[str, torch.Tensor] = {"weight": torch.randn(10, 10)}

        source_path: Path = temp_dir / "model.safetensors"
        save_file(tensors, str(source_path))

        output_path: Path = temp_dir / "output_model"

        result: Path | None = converter._convert_safetensors_to_pytorch(
            source_path,
            output_path,
        )

        assert result is not None, "Conversion must succeed"
        assert result.suffix == ".pt", "Must add .pt extension"


class TestConversionValidation:
    """Production tests for conversion validation."""

    @pytest.fixture
    def converter(self) -> ModelFormatConverter:
        """Create converter for testing."""
        return ModelFormatConverter()

    @pytest.fixture
    def temp_dir(self) -> Generator[Path, None, None]:
        """Create temporary directory."""
        with tempfile.TemporaryDirectory(prefix="validation_test_") as tmp:
            yield Path(tmp)

    @pytest.mark.skipif(not (HAS_TORCH and HAS_ONNX), reason="PyTorch and ONNX required")
    def test_validate_conversion_with_matching_outputs(self, converter: ModelFormatConverter, temp_dir: Path) -> None:
        """Validation passes when model outputs match."""

        class SimpleModel(torch.nn.Module):
            def __init__(self) -> None:
                super().__init__()
                self.linear: torch.nn.Linear = torch.nn.Linear(10, 5)
                torch.nn.init.constant_(self.linear.weight, 0.1)
                torch.nn.init.constant_(self.linear.bias, 0.0)

            def forward(self, x: torch.Tensor) -> torch.Tensor:
                result: torch.Tensor = self.linear(x)
                return result

        model = SimpleModel()
        model.eval()

        pytorch_path: Path = temp_dir / "model.pt"
        torch.save(model, str(pytorch_path))

        onnx_path: Path = temp_dir / "model.onnx"
        converter._convert_pytorch_to_onnx(
            pytorch_path,
            onnx_path,
            input_shape=(1, 10),
        )

        test_input: NDArray[np.floating[Any]] = np.random.randn(1, 10).astype(np.float32)

        is_valid: bool = converter.validate_conversion(
            pytorch_path,
            onnx_path,
            test_inputs={"input": test_input},
            tolerance=1e-3,
        )

        assert is_valid, "Validation must pass for correct conversion"

    def test_validate_conversion_fails_for_unknown_format(self, converter: ModelFormatConverter, temp_dir: Path) -> None:
        """Validation fails gracefully for unknown formats."""
        file1: Path = temp_dir / "model.unknown"
        file2: Path = temp_dir / "model2.unknown"

        file1.write_text("data")
        file2.write_text("data")

        is_valid: bool = converter.validate_conversion(file1, file2)

        assert not is_valid, "Must fail for unknown formats"


class TestHighLevelConversion:
    """Production tests for high-level convert_model API."""

    @pytest.fixture
    def converter(self) -> ModelFormatConverter:
        """Create converter for testing."""
        return ModelFormatConverter()

    @pytest.fixture
    def temp_dir(self) -> Generator[Path, None, None]:
        """Create temporary directory."""
        with tempfile.TemporaryDirectory(prefix="highlevel_test_") as tmp:
            yield Path(tmp)

    @pytest.mark.skipif(not (HAS_TORCH and HAS_SAFETENSORS), reason="PyTorch and SafeTensors required")
    def test_convert_model_detects_formats_automatically(self, converter: ModelFormatConverter, temp_dir: Path) -> None:
        """convert_model automatically detects source format."""
        state_dict: dict[str, torch.Tensor] = {"weight": torch.randn(50, 25)}

        source: Path = temp_dir / "model.pt"
        torch.save(state_dict, str(source))

        output: Path = temp_dir / "model.safetensors"

        result: Path | None = converter.convert_model(
            source,
            "safetensors",
            output,
        )

        assert result is not None, "Conversion must succeed"
        assert result.exists(), "Output file must be created"

    @pytest.mark.skipif(not (HAS_TORCH and HAS_SAFETENSORS), reason="PyTorch and SafeTensors required")
    def test_convert_model_generates_output_path(self, converter: ModelFormatConverter, temp_dir: Path) -> None:
        """convert_model auto-generates output path if not provided."""
        state_dict: dict[str, torch.Tensor] = {"weight": torch.randn(10, 10)}

        source: Path = temp_dir / "my_model.pt"
        torch.save(state_dict, str(source))

        result: Path | None = converter.convert_model(
            source,
            "safetensors",
        )

        assert result is not None, "Conversion must succeed"
        assert "my_model_safetensors" in str(result), "Output name must be derived from source"

    def test_convert_model_fails_for_unsupported_conversion(self, converter: ModelFormatConverter, temp_dir: Path) -> None:
        """convert_model returns None for unsupported conversions."""
        test_file: Path = temp_dir / "model.pt"
        test_file.write_text("fake model")

        result: Path | None = converter.convert_model(
            test_file,
            "unsupported_format",
        )

        assert result is None, "Must return None for unsupported format"

    def test_convert_model_fails_for_nonexistent_file(self, converter: ModelFormatConverter, temp_dir: Path) -> None:
        """convert_model handles missing source files gracefully."""
        nonexistent: Path = temp_dir / "does_not_exist.pt"

        result: Path | None = converter.convert_model(
            nonexistent,
            "onnx",
        )

        assert result is None, "Must return None for missing file"


class TestModelInfo:
    """Production tests for model information extraction."""

    @pytest.fixture
    def converter(self) -> ModelFormatConverter:
        """Create converter for testing."""
        return ModelFormatConverter()

    @pytest.fixture
    def temp_dir(self) -> Generator[Path, None, None]:
        """Create temporary directory."""
        with tempfile.TemporaryDirectory(prefix="info_test_") as tmp:
            yield Path(tmp)

    @pytest.mark.skipif(not HAS_TORCH, reason="PyTorch not available")
    def test_get_model_info_for_pytorch(self, converter: ModelFormatConverter, temp_dir: Path) -> None:
        """get_model_info extracts metadata from PyTorch models."""
        state_dict: dict[str, torch.Tensor] = {
            "layer1": torch.randn(100, 50),
            "layer2": torch.randn(50, 10),
        }

        model_path: Path = temp_dir / "model.pt"
        torch.save(state_dict, str(model_path))

        info: dict[str, Any] = converter.get_model_info(model_path)

        assert info is not None, "Must return model info"
        assert "format" in info, "Must include format"
        assert info["format"] == "pytorch", "Must identify as PyTorch"

        if "num_parameters" in info:
            assert info["num_parameters"] > 0, "Must count parameters"
