"""Model Format Converter for Intellicrack.

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

from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

from intellicrack.handlers.numpy_handler import numpy as np
from intellicrack.utils.type_safety import ensure_dict, get_kwarg_typed, get_typed_item, validate_type

from ..utils.logger import get_logger


GPU_AUTOLOADER_AVAILABLE = False
get_device: Callable[[], str] | None = None
get_gpu_info: Callable[[], dict[str, Any] | None] | None = None
to_device: Callable[[Any, str | None], Any] | None = None
memory_allocated: Callable[[], int] | None = None
memory_reserved: Callable[[], int] | None = None
empty_cache: Callable[[], None] | None = None
gpu_autoloader: Callable[[Any], Any] | None = None

try:
    from ..utils.gpu_autoloader import (
        get_device as _get_device,
        get_gpu_info as _get_gpu_info,
        gpu_autoloader as _gpu_autoloader,
    )

    get_device = _get_device
    get_gpu_info = _get_gpu_info

    try:
        from ..utils.gpu_autoloader import to_device as _to_device

        to_device = _to_device  # type: ignore[assignment]
    except (ImportError, AttributeError):
        pass

    try:
        from ..utils.gpu_autoloader import memory_allocated as _memory_allocated  # type: ignore[attr-defined]

        memory_allocated = _memory_allocated
    except (ImportError, AttributeError):
        pass

    try:
        from ..utils.gpu_autoloader import memory_reserved as _memory_reserved  # type: ignore[attr-defined]

        memory_reserved = _memory_reserved
    except (ImportError, AttributeError):
        pass

    try:
        from ..utils.gpu_autoloader import empty_cache as _empty_cache  # type: ignore[attr-defined]

        empty_cache = _empty_cache
    except (ImportError, AttributeError):
        pass

    gpu_autoloader = _gpu_autoloader  # type: ignore[assignment]
    GPU_AUTOLOADER_AVAILABLE = True
except ImportError:
    pass

try:
    import torch

    HAS_TORCH = True
except ImportError:
    torch = None  # type: ignore[assignment]
    HAS_TORCH = False

logger = get_logger(__name__)

tf: Any = None
try:
    # Fix PyTorch + TensorFlow import conflict by using GNU threading layer
    import os

    os.environ["MKL_THREADING_LAYER"] = "GNU"

    from intellicrack.handlers.tensorflow_handler import tf

    HAS_TF = True
except ImportError as e:
    logger.exception("Import error in model_format_converter: %s", e)
    HAS_TF = False

try:
    import onnx
    import onnxruntime as ort

    HAS_ONNX = True
except ImportError as e:
    logger.exception("Import error in model_format_converter: %s", e)
    onnx = None  # type: ignore[assignment]
    ort = None
    HAS_ONNX = False

try:
    from transformers import AutoConfig, AutoModel, AutoModelForCausalLM, AutoTokenizer

    HAS_TRANSFORMERS = True
except ImportError as e:
    logger.exception("Import error in model_format_converter: %s", e)
    AutoConfig = None  # type: ignore[misc, assignment]
    AutoModel = None  # type: ignore[misc, assignment]
    AutoModelForCausalLM = None  # type: ignore[misc, assignment]
    AutoTokenizer = None  # type: ignore[misc, assignment]
    HAS_TRANSFORMERS = False

safe_open: Any = None
save_file: Any = None
HAS_SAFETENSORS = False

try:
    from safetensors import safe_open as _safe_open
    from safetensors.torch import save_file as _save_file

    safe_open = _safe_open
    save_file = _save_file
    HAS_SAFETENSORS = True
except ImportError as e:
    logger.exception("Import error in model_format_converter: %s", e)


class ModelFormatConverter:
    """Converts models between different formats."""

    def __init__(self) -> None:
        """Initialize the model format converter."""
        self.supported_conversions = self._get_supported_conversions()
        self.gpu_info = None

        # Get GPU information if available
        if GPU_AUTOLOADER_AVAILABLE and get_gpu_info:
            try:
                self.gpu_info = get_gpu_info()
                if self.gpu_info:
                    logger.info("GPU available for conversion: %s", self.gpu_info)
            except Exception as e:
                logger.debug("Could not get GPU info: %s", e)

        logger.info("Model converter initialized with conversions: %s", self.supported_conversions)

    def _get_supported_conversions(self) -> dict[str, list[str]]:
        """Get list of supported format conversions.

        Returns:
            Dictionary of source_format -> [target_formats]

        """
        conversions: dict[str, list[str]] = {
            "pytorch": [],
            "tensorflow": [],
            "onnx": [],
            "safetensors": [],
        }

        # PyTorch conversions
        if HAS_ONNX:
            conversions["pytorch"].append("onnx")
        if HAS_SAFETENSORS:
            conversions["pytorch"].append("safetensors")
            conversions["safetensors"].append("pytorch")

        # TensorFlow conversions
        if HAS_TF and HAS_ONNX:
            conversions["tensorflow"].append("onnx")

        # ONNX conversions
        if HAS_ONNX and HAS_TF:
            conversions["onnx"].append("tensorflow")

        return conversions

    def convert_model(
        self,
        source_path: str | Path,
        target_format: str,
        output_path: str | Path | None = None,
        **kwargs: object,
    ) -> Path | None:
        """Convert a model to a different format.

        Args:
            source_path: Path to source model
            target_format: Target format ("onnx", "safetensors", etc.)
            output_path: Output path (auto-generated if None)
            **kwargs: Additional conversion options

        Returns:
            Path to converted model or None

        """
        source_path = Path(source_path)

        # Detect source format
        source_format = self._detect_format(source_path)
        if not source_format:
            logger.exception("Could not detect format of %s", source_path)
            return None

        # Check if conversion is supported
        if target_format not in self.supported_conversions.get(source_format, []):
            logger.exception("Conversion from %s to %s not supported", source_format, target_format)
            return None

        # Generate output path if needed
        if output_path is None:
            output_path = source_path.parent / f"{source_path.stem}_{target_format}"
        else:
            output_path = Path(output_path)

        if GPU_AUTOLOADER_AVAILABLE and memory_allocated and memory_reserved:
            try:
                initial_allocated = memory_allocated()
                initial_reserved = memory_reserved()
                logger.info(
                    "GPU memory before conversion - Allocated: %.1fMB, Reserved: %.1fMB",
                    initial_allocated / (1024**2),
                    initial_reserved / (1024**2),
                )
            except Exception as e:
                logger.debug("Unable to get GPU memory stats: %s", e)

        converter_method = f"_convert_{source_format}_to_{target_format}"
        if hasattr(self, converter_method):
            try:
                result = cast(
                    "Path | None",
                    getattr(self, converter_method)(source_path, output_path, **kwargs),
                )

                if GPU_AUTOLOADER_AVAILABLE and empty_cache:
                    try:
                        empty_cache()
                        logger.debug("Cleared GPU cache after conversion")
                    except Exception as e:
                        logger.debug("Failed to clear GPU cache: %s", e)

                if GPU_AUTOLOADER_AVAILABLE and memory_allocated and memory_reserved:
                    try:
                        final_allocated = memory_allocated()
                        final_reserved = memory_reserved()
                        logger.info(
                            "GPU memory after conversion - Allocated: %.1fMB, Reserved: %.1fMB",
                            final_allocated / (1024**2),
                            final_reserved / (1024**2),
                        )
                    except Exception as e:
                        logger.debug("Unable to get final GPU memory stats: %s", e)

                return result
            except Exception as e:
                logger.exception("Conversion failed: %s", e)
                return None
        else:
            logger.exception("Converter method %s not implemented", converter_method)
            return None

    def _detect_format(self, model_path: Path) -> str | None:
        """Detect the format of a model.

        Args:
            model_path: Path to model file or directory

        Returns:
            Format string or None

        """
        if model_path.is_file():
            # Check file extensions
            if model_path.suffix in [".pt", ".pth", ".bin"]:
                return "pytorch"
            if model_path.suffix == ".onnx":
                return "onnx"
            if model_path.suffix in [".pb", ".h5"]:
                return "tensorflow"
            if model_path.suffix == ".safetensors":
                return "safetensors"

        elif model_path.is_dir():
            # Check for framework-specific files
            if (model_path / "pytorch_model.bin").exists():
                return "pytorch"
            if (model_path / "model.safetensors").exists():
                return "safetensors"
            if (model_path / "saved_model.pb").exists():
                return "tensorflow"
            if any(model_path.glob("*.onnx")):
                return "onnx"

        return None

    def _convert_pytorch_to_onnx(
        self,
        source_path: Path,
        output_path: Path,
        **kwargs: object,
    ) -> Path | None:
        """Convert PyTorch model to ONNX.

        Args:
            source_path: Path to PyTorch model
            output_path: Output path for ONNX model
            **kwargs: Conversion options

        Returns:
            Path to ONNX model or None

        """
        if not HAS_ONNX:
            logger.exception("ONNX not available for conversion")
            return None

        if not HAS_TORCH:
            logger.exception("PyTorch not available for conversion")
            return None

        try:
            if source_path.is_dir():
                if not HAS_TRANSFORMERS or AutoModelForCausalLM is None or AutoConfig is None or torch is None:
                    logger.exception("transformers, AutoModelForCausalLM, AutoConfig, and torch required for HF models")
                    return None

                device = "cpu"
                if GPU_AUTOLOADER_AVAILABLE and get_device:
                    device = get_device()
                elif torch.cuda.is_available():
                    device = "cuda"

                model = AutoModelForCausalLM.from_pretrained(
                    str(source_path),
                    torch_dtype=torch.float32,
                    device_map=device if device != "cpu" else None,
                )

                config = AutoConfig.from_pretrained(str(source_path))

                batch_size_val = get_typed_item(kwargs, "batch_size", int, 1)
                sequence_length_val = get_typed_item(kwargs, "sequence_length", int, 128)

                sample_input = torch.randint(
                    0,
                    config.vocab_size,
                    (batch_size_val, sequence_length_val),
                    dtype=torch.long,
                )
            else:
                device = "cpu"
                if GPU_AUTOLOADER_AVAILABLE and get_device:
                    device = get_device()
                elif torch.cuda.is_available():
                    device = "cuda"

                model = torch.load(source_path, map_location=device)

                input_shape_val = kwargs.get("input_shape")
                if not input_shape_val:
                    logger.exception("input_shape required for standalone PyTorch models")
                    return None

                input_shape_tuple = validate_type(input_shape_val, tuple, "input_shape")
                sample_input = torch.randn(*input_shape_tuple)

            model.eval()  # type: ignore[no-untyped-call]

            if GPU_AUTOLOADER_AVAILABLE and to_device and device != "cpu":
                try:
                    model = to_device(model, device)
                    sample_input = to_device(sample_input, device)
                    logger.info("Model and inputs moved to %s for conversion", device)
                except Exception as e:
                    logger.debug("Could not move to GPU, continuing on CPU: %s", e)

            output_path.parent.mkdir(parents=True, exist_ok=True)

            dynamic_axes_default: dict[str, dict[int, str]] = {
                "input_ids": {0: "batch_size", 1: "sequence"},
                "output": {0: "batch_size", 1: "sequence"},
            }
            dynamic_axes_val = kwargs.get("dynamic_axes", dynamic_axes_default)
            if not isinstance(dynamic_axes_val, dict):
                dynamic_axes_val = dynamic_axes_default

            opset_version_val = get_typed_item(kwargs, "opset_version", int, 14)
            do_constant_folding_val = get_typed_item(kwargs, "do_constant_folding", bool, True)
            input_names_val = get_typed_item(kwargs, "input_names", list, ["input_ids"])
            output_names_val = get_typed_item(kwargs, "output_names", list, ["output"])
            verbose_val = get_typed_item(kwargs, "verbose", bool, False)

            torch.onnx.export(
                model,
                (sample_input,),
                str(output_path),
                export_params=True,
                opset_version=opset_version_val,
                do_constant_folding=do_constant_folding_val,
                input_names=input_names_val,
                output_names=output_names_val,
                dynamic_axes=dynamic_axes_val,
                verbose=verbose_val,
            )

            onnx_model = onnx.load(str(output_path))
            onnx.checker.check_model(onnx_model)

            logger.info("Successfully converted PyTorch model to ONNX: %s", output_path)
            return output_path

        except Exception as e:
            logger.exception("Failed to convert PyTorch to ONNX: %s", e)
            return None

    def _convert_pytorch_to_safetensors(
        self,
        source_path: Path,
        output_path: Path,
        **kwargs: object,
    ) -> Path | None:
        """Convert PyTorch model to SafeTensors.

        Args:
            source_path: Path to PyTorch model
            output_path: Output path for SafeTensors
            **kwargs: Conversion options

        Returns:
            Path to SafeTensors file or None

        """
        if not HAS_SAFETENSORS or save_file is None:
            logger.exception("safetensors not available for conversion")
            return None

        if not HAS_TORCH or torch is None:
            logger.exception("torch not available for conversion")
            return None

        try:
            state_dict: dict[str, Any] = {}
            if source_path.is_dir():
                model_files = list(source_path.glob("*.bin")) + list(source_path.glob("*.pt"))
                if not model_files:
                    logger.exception("No PyTorch model files found")
                    return None

                for model_file in model_files:
                    device = "cpu"
                    if GPU_AUTOLOADER_AVAILABLE and get_device:
                        device = get_device()
                    elif HAS_TORCH and torch.cuda.is_available():
                        device = "cuda"

                    state_dict |= torch.load(model_file, map_location=device)
            else:
                device = "cpu"
                if GPU_AUTOLOADER_AVAILABLE and get_device:
                    device = get_device()
                elif HAS_TORCH and torch.cuda.is_available():
                    device = "cuda"

                loaded = torch.load(source_path, map_location=device)
                if isinstance(loaded, dict):
                    state_dict = loaded
                elif hasattr(loaded, "state_dict"):
                    state_dict_method = loaded.state_dict
                    if callable(state_dict_method):
                        state_dict = state_dict_method()
                else:
                    logger.exception("Unable to extract state dict from loaded model")
                    return None

            output_path.parent.mkdir(parents=True, exist_ok=True)

            if output_path.suffix != ".safetensors":
                output_path = output_path.with_suffix(".safetensors")

            if GPU_AUTOLOADER_AVAILABLE and gpu_autoloader and device != "cpu":
                try:
                    optimized_dict: dict[str, Any] = {}
                    for key, tensor in state_dict.items():
                        if hasattr(tensor, "shape"):
                            optimized_tensor = gpu_autoloader(tensor)
                            optimized_dict[key] = optimized_tensor if optimized_tensor is not None else tensor
                        else:
                            optimized_dict[key] = tensor
                    state_dict = optimized_dict
                    logger.debug("Applied GPU optimizations to state dict before saving")
                except Exception as e:
                    logger.debug("Could not apply GPU optimizations: %s", e)

            metadata_raw = kwargs.get("metadata", {})
            metadata_val: dict[str, str] = {}
            if isinstance(metadata_raw, dict):
                for k, v in metadata_raw.items():
                    if isinstance(k, str) and isinstance(v, str):
                        metadata_val[k] = v

            save_file(state_dict, str(output_path), metadata=metadata_val)

            logger.info("Successfully converted PyTorch model to SafeTensors: %s", output_path)
            return output_path

        except Exception as e:
            logger.exception("Failed to convert PyTorch to SafeTensors: %s", e)
            return None

    def _convert_safetensors_to_pytorch(
        self,
        source_path: Path,
        output_path: Path,
        **kwargs: object,
    ) -> Path | None:
        """Convert SafeTensors to PyTorch format.

        Args:
            source_path: Path to SafeTensors file
            output_path: Output path for PyTorch model
            **kwargs: Conversion options

        Returns:
            Path to PyTorch model or None

        """
        if not HAS_SAFETENSORS or safe_open is None:
            logger.exception("safetensors not available for conversion")
            return None

        if not HAS_TORCH or torch is None:
            logger.exception("torch not available for conversion")
            return None

        try:
            device_val = get_kwarg_typed(kwargs, "device", str, "cpu")
            dtype_val = kwargs.get("dtype")
            preserve_layout_val = get_kwarg_typed(kwargs, "preserve_layout", bool, True)

            state_dict: dict[str, Any] = {}
            with safe_open(str(source_path), framework="pt", device=device_val) as f:
                for key in f:
                    tensor = f.get_tensor(key)
                    if dtype_val and isinstance(dtype_val, str) and hasattr(torch, dtype_val):
                        torch_dtype = getattr(torch, dtype_val)
                        tensor = tensor.to(torch_dtype)
                    state_dict[key] = tensor

            output_path.parent.mkdir(parents=True, exist_ok=True)

            if output_path.suffix not in [".pt", ".pth", ".bin"]:
                output_path = output_path.with_suffix(".pt")

            save_kwargs: dict[str, Any] = {}
            if not preserve_layout_val:
                save_kwargs["_use_new_zipfile_serialization"] = False
            torch.save(state_dict, str(output_path), **save_kwargs)

            logger.info("Successfully converted SafeTensors to PyTorch: %s", output_path)
            return output_path

        except Exception as e:
            logger.exception("Failed to convert SafeTensors to PyTorch: %s", e)
            return None

    def _convert_tensorflow_to_onnx(
        self,
        source_path: Path,
        output_path: Path,
        **kwargs: object,
    ) -> Path | None:
        """Convert TensorFlow model to ONNX.

        Args:
            source_path: Path to TensorFlow model
            output_path: Output path for ONNX model
            **kwargs: Conversion options

        Returns:
            Path to ONNX model or None

        """
        if not HAS_TF or not HAS_ONNX or tf is None:
            logger.exception("TensorFlow and ONNX required for conversion")
            return None

        try:
            try:
                import tf2onnx

                if source_path.is_dir():
                    model = tf.saved_model.load(str(source_path))
                elif hasattr(tf, "keras"):
                    model = tf.keras.models.load_model(str(source_path))
                else:
                    raise ImportError("TensorFlow keras module not available")

                concrete_func: Any = None
                if hasattr(model, "signatures"):
                    signature_key_val = get_kwarg_typed(kwargs, "signature_key", str, "serving_default")
                    concrete_func = model.signatures[signature_key_val]
                else:
                    input_spec_val = kwargs.get("input_spec")
                    if not input_spec_val:
                        logger.exception("input_spec required for Keras models")
                        return None

                    @tf.function  # type: ignore[untyped-decorator]
                    def inference_func(x: Any) -> Any:
                        return model(x)

                    concrete_func = inference_func.get_concrete_function(input_spec_val)

                output_path.parent.mkdir(parents=True, exist_ok=True)

                opset_val = get_kwarg_typed(kwargs, "opset_version", int, 14)
                model_proto, _ = tf2onnx.convert.from_function(
                    concrete_func,
                    opset=opset_val,
                    output_path=str(output_path),
                )

                # Log model info
                if model_proto:
                    logger.info("Successfully converted TensorFlow model to ONNX: %s", output_path)
                    logger.debug("ONNX model graph nodes: %s", len(model_proto.graph.node))
                else:
                    logger.warning("Model conversion completed but model_proto is None")

                return output_path

            except ImportError:
                logger.exception("tf2onnx required for TensorFlow to ONNX conversion")
                return None

        except Exception as e:
            logger.exception("Failed to convert TensorFlow to ONNX: %s", e)
            return None

    def validate_conversion(
        self,
        original_path: Path,
        converted_path: Path,
        test_inputs: dict[str, np.ndarray] | None = None,
        tolerance: float = 1e-5,
    ) -> bool:
        """Validate that conversion preserved model behavior.

        Args:
            original_path: Path to original model
            converted_path: Path to converted model
            test_inputs: Test inputs for validation
            tolerance: Numerical tolerance for output comparison

        Returns:
            True if validation passed

        """
        try:
            # Detect formats
            original_format = self._detect_format(original_path)
            converted_format = self._detect_format(converted_path)

            if not original_format or not converted_format:
                logger.exception("Could not detect model formats")
                return False

            # Generate test inputs if not provided
            if test_inputs is None:
                # Simple default test input
                test_inputs = {
                    "input": np.random.randn(1, 224, 224, 3).astype(np.float32),
                }

            # Get outputs from both models
            original_output = self._run_inference(
                original_path,
                original_format,
                test_inputs,
            )
            converted_output = self._run_inference(
                converted_path,
                converted_format,
                test_inputs,
            )

            if original_output is None or converted_output is None:
                return False

            # Compare outputs
            for key in original_output:
                if key not in converted_output:
                    logger.exception("Output key '%s' missing in converted model", key)
                    return False

                # Numerical comparison
                diff = np.abs(original_output[key] - converted_output[key])
                max_diff = np.max(diff)

                if max_diff > tolerance:
                    logger.exception(
                        "Output mismatch for '%s': max difference %s > %s",
                        key,
                        max_diff,
                        tolerance,
                    )
                    return False

            logger.info("Conversion validation passed")
            return True

        except Exception as e:
            logger.exception("Validation failed: %s", e)
            return False

    def _run_inference(
        self,
        model_path: Path,
        format: str,
        inputs: dict[str, np.ndarray],
    ) -> dict[str, np.ndarray] | None:
        """Run inference on a model.

        Args:
            model_path: Path to model
            format: Model format
            inputs: Input dictionary

        Returns:
            Output dictionary or None

        """
        try:
            if format == "onnx" and HAS_ONNX and ort is not None:
                session = ort.InferenceSession(str(model_path))
                outputs = session.run(None, inputs)

                output_names = [o.name for o in session.get_outputs()]
                return dict(zip(output_names, outputs, strict=False))

            if format == "pytorch" and HAS_TORCH and torch is not None:
                device = "cpu"
                if GPU_AUTOLOADER_AVAILABLE and get_device:
                    device = get_device()
                elif torch.cuda.is_available():
                    device = "cuda"

                model = torch.load(model_path, map_location=device)
                model.eval()

                with torch.no_grad():
                    torch_inputs = {k: torch.from_numpy(v) for k, v in inputs.items()}

                    if GPU_AUTOLOADER_AVAILABLE and to_device:
                        torch_inputs = {k: to_device(v, device) for k, v in torch_inputs.items()}
                        model = to_device(model, device)

                    output: Any = None
                    if isinstance(model, torch.nn.Module):
                        output = model(torch_inputs["input"])
                    else:
                        output = model(**torch_inputs)

                    if isinstance(output, dict):
                        return {k: v.cpu().numpy() for k, v in output.items()}
                    return {"output": output.cpu().numpy()}

            if format == "tensorflow" and HAS_TF and tf is not None:
                model = tf.saved_model.load(str(model_path))

                infer = model.signatures.get("serving_default", model)

                outputs = infer(**inputs)

                return {k: v.numpy() for k, v in outputs.items()}

            logger.exception("Inference not supported for format: %s", format)
            return None

        except Exception as e:
            logger.exception("Inference failed: %s", e)
            return None

    def get_model_info(self, model_path: Path) -> dict[str, Any]:
        """Get information about a model.

        Args:
            model_path: Path to model

        Returns:
            Dictionary with model information

        """
        info: dict[str, Any] = {
            "path": str(model_path),
            "format": self._detect_format(model_path),
            "size_mb": 0.0,
            "parameters": {},
            "metadata": {},
        }

        if model_path.is_file():
            info["size_mb"] = model_path.stat().st_size / (1024 * 1024)
        elif model_path.is_dir():
            total_size = sum(f.stat().st_size for f in model_path.rglob("*") if f.is_file())
            info["size_mb"] = total_size / (1024 * 1024)

        if info["format"] == "onnx" and HAS_ONNX and onnx is not None:
            try:
                model = onnx.load(str(model_path))
                params_dict: dict[str, Any] = info["parameters"]
                params_dict["inputs"] = [
                    {
                        "name": i.name,
                        "shape": [d.dim_value for d in i.type.tensor_type.shape.dim],
                    }
                    for i in model.graph.input
                ]
                params_dict["outputs"] = [
                    {
                        "name": o.name,
                        "shape": [d.dim_value for d in o.type.tensor_type.shape.dim],
                    }
                    for o in model.graph.output
                ]
                metadata_dict: dict[str, Any] = info["metadata"]
                metadata_dict["opset_version"] = model.opset_import[0].version
            except Exception as e:
                logger.debug("Could not get ONNX model metadata: %s", e)

        return info

    def load_model_for_conversion(self, model_path: str | Path, model_type: str = "auto") -> Any:
        """Load a model using appropriate AutoModel class based on type.

        Args:
            model_path: Path to model
            model_type: Type of model (auto, base, causal_lm, seq2seq, classification, etc.)

        Returns:
            Loaded model or None

        """
        if not HAS_TRANSFORMERS or AutoModel is None:
            logger.exception("transformers with AutoModel required")
            return None

        try:
            model_path_obj = Path(model_path)

            model_loaders: dict[str, Any] = {
                "auto": AutoModel,
                "base": AutoModel,
                "causal_lm": AutoModelForCausalLM,
                "seq2seq": lambda path: AutoModel.from_pretrained(path, trust_remote_code=True),
                "classification": lambda path: AutoModel.from_pretrained(path, num_labels=2),
                "token_classification": lambda path: AutoModel.from_pretrained(path, num_labels=9),
                "question_answering": AutoModel.from_pretrained,
                "feature_extraction": AutoModel,
            }

            loader = model_loaders.get(model_type, AutoModel)

            model: Any = None
            if callable(loader) and hasattr(loader, "from_pretrained"):
                model = loader.from_pretrained(str(model_path_obj))
            elif callable(loader):
                model = loader(str(model_path_obj))
            else:
                model = AutoModel.from_pretrained(str(model_path_obj))

            logger.info("Successfully loaded model from %s as %s", model_path_obj, model_type)
            return model

        except Exception as e:
            logger.exception("Failed to load model: %s", e)
            return None

    def analyze_model_architecture(self, model_path: str | Path) -> dict[str, Any] | None:
        """Analyze model architecture using AutoModel to determine conversion requirements.

        Args:
            model_path: Path to model

        Returns:
            Dictionary with architecture details or None

        """
        if not HAS_TRANSFORMERS or AutoModel is None or AutoConfig is None:
            logger.exception("transformers with AutoModel required")
            return None

        try:
            config = AutoConfig.from_pretrained(str(model_path))

            model = AutoModel.from_pretrained(
                str(model_path),
                output_loading_info=True,
            )

            architecture_info: dict[str, Any] = {
                "model_type": config.model_type,
                "architectures": getattr(config, "architectures", []),
                "hidden_size": getattr(config, "hidden_size", None),
                "num_layers": getattr(config, "num_hidden_layers", None),
                "num_attention_heads": getattr(config, "num_attention_heads", None),
                "vocab_size": getattr(config, "vocab_size", None),
                "max_position_embeddings": getattr(config, "max_position_embeddings", None),
                "num_parameters": sum(p.numel() for p in model.parameters()),
                "requires_grad_params": sum(p.numel() for p in model.parameters() if p.requires_grad),
                "model_class": model.__class__.__name__,
                "supports_gradient_checkpointing": hasattr(model, "gradient_checkpointing_enable"),
                "is_quantized": hasattr(model, "quantization_config"),
                "device_map": getattr(model, "hf_device_map", None),
            }

            del model
            if GPU_AUTOLOADER_AVAILABLE and empty_cache:
                empty_cache()
            elif HAS_TORCH and torch is not None and torch.cuda.is_available():
                torch.cuda.empty_cache()

            return architecture_info

        except Exception as e:
            logger.exception("Failed to analyze model architecture: %s", e)
            return None

    def convert_model_with_automodel(
        self,
        source_path: str | Path,
        target_format: str,
        model_type: str = "auto",
        **kwargs: object,
    ) -> Path | None:
        """Convert a model using AutoModel for flexible model loading.

        Args:
            source_path: Path to source model
            target_format: Target format
            model_type: Type of model for loading
            **kwargs: Additional conversion parameters

        Returns:
            Path to converted model or None

        """
        model = self.load_model_for_conversion(source_path, model_type)
        if model is None:
            return None

        source_path_obj = Path(source_path)
        output_path_val = kwargs.get("output_path", source_path_obj.parent / f"{source_path_obj.stem}_{target_format}")
        output_path_obj: Path
        if isinstance(output_path_val, Path):
            output_path_obj = output_path_val
        else:
            output_path_obj = Path(validate_type(output_path_val, str, "output_path"))

        try:
            if target_format == "onnx" and HAS_ONNX and HAS_TORCH and torch is not None and AutoConfig is not None:
                model.eval()

                config = AutoConfig.from_pretrained(str(source_path))
                batch_size_val = get_typed_item(kwargs, "batch_size", int, 1)
                seq_length_val = get_typed_item(kwargs, "sequence_length", int, 128)

                sample_input: Any = None
                if hasattr(config, "vocab_size"):
                    sample_input = torch.randint(0, config.vocab_size, (batch_size_val, seq_length_val))
                else:
                    input_shape_val = kwargs.get("input_shape", (batch_size_val, 3, 224, 224))
                    input_shape_tuple = validate_type(input_shape_val, tuple, "input_shape")
                    sample_input = torch.randn(*input_shape_tuple)

                opset_version_val = get_typed_item(kwargs, "opset_version", int, 14)
                input_names_val = get_typed_item(kwargs, "input_names", list, ["input"])
                output_names_val = get_typed_item(kwargs, "output_names", list, ["output"])
                dynamic_axes_default: dict[str, dict[int, str]] = {"input": {0: "batch_size"}, "output": {0: "batch_size"}}
                dynamic_axes_val = kwargs.get("dynamic_axes", dynamic_axes_default)
                if not isinstance(dynamic_axes_val, dict):
                    dynamic_axes_val = dynamic_axes_default

                torch.onnx.export(
                    model,
                    sample_input,
                    str(output_path_obj),
                    export_params=True,
                    opset_version=opset_version_val,
                    input_names=input_names_val,
                    output_names=output_names_val,
                    dynamic_axes=dynamic_axes_val,
                )

                logger.info("Successfully converted model to %s using AutoModel", target_format)
                return output_path_obj

            logger.exception("Conversion to %s not supported with AutoModel method", target_format)
            return None

        except Exception as e:
            logger.exception("Failed to convert model with AutoModel: %s", e)
            return None
        finally:
            del model
            if GPU_AUTOLOADER_AVAILABLE and empty_cache:
                empty_cache()
            elif HAS_TORCH and torch is not None and torch.cuda.is_available():
                torch.cuda.empty_cache()


_CONVERTER: ModelFormatConverter | None = None


def get_model_converter() -> ModelFormatConverter:
    """Get the global model format converter.

    Returns:
        ModelFormatConverter: The global model format converter instance.

    """
    global _CONVERTER
    if _CONVERTER is None:
        _CONVERTER = ModelFormatConverter()
    return _CONVERTER
