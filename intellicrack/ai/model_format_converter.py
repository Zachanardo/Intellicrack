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

from pathlib import Path
from typing import Any, TypeVar

from intellicrack.handlers.numpy_handler import numpy as np

from ..utils.logger import get_logger


# Try to import GPU autoloader
GPU_AUTOLOADER_AVAILABLE = False
get_device = None
get_gpu_info = None
to_device = None
memory_allocated = None
memory_reserved = None
empty_cache = None
gpu_autoloader = None

try:
    from ..utils.gpu_autoloader import empty_cache, get_device, get_gpu_info, gpu_autoloader, memory_allocated, memory_reserved, to_device

    GPU_AUTOLOADER_AVAILABLE = True
except ImportError:
    pass

try:
    import torch

    HAS_TORCH = True
except ImportError:
    torch = None
    HAS_TORCH = False

logger = get_logger(__name__)

# Try to import conversion libraries
try:
    import onnx
    import onnxruntime as ort

    HAS_ONNX = True
except ImportError as e:
    logger.error("Import error in model_format_converter: %s", e)
    onnx = None
    ort = None
    HAS_ONNX = False

try:
    # Fix PyTorch + TensorFlow import conflict by using GNU threading layer
    import os

    os.environ["MKL_THREADING_LAYER"] = "GNU"

    from intellicrack.handlers.tensorflow_handler import tensorflow as tf

    HAS_TF = True
except ImportError as e:
    logger.error("Import error in model_format_converter: %s", e)
    tf = None
    HAS_TF = False

try:
    from transformers import AutoConfig, AutoModel, AutoModelForCausalLM, AutoTokenizer

    HAS_TRANSFORMERS = True
except ImportError as e:
    logger.error("Import error in model_format_converter: %s", e)
    AutoConfig = None
    AutoModel = None
    AutoModelForCausalLM = None
    AutoTokenizer = None
    HAS_TRANSFORMERS = False

try:
    from safetensors import safe_open
    from safetensors.torch import save_file

    HAS_SAFETENSORS = True
except ImportError as e:
    logger.error("Import error in model_format_converter: %s", e)
    safe_open = None
    save_file = None
    HAS_SAFETENSORS = False


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
                    logger.info(f"GPU available for conversion: {self.gpu_info}")
            except Exception as e:
                logger.debug(f"Could not get GPU info: {e}")

        logger.info(f"Model converter initialized with conversions: {self.supported_conversions}")

    def _get_supported_conversions(self) -> dict[str, list[str]]:
        """Get list of supported format conversions.

        Returns:
            Dictionary of source_format -> [target_formats]

        """
        conversions = {
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
            logger.error(f"Could not detect format of {source_path}")
            return None

        # Check if conversion is supported
        if target_format not in self.supported_conversions.get(source_format, []):
            logger.error(f"Conversion from {source_format} to {target_format} not supported")
            return None

        # Generate output path if needed
        if output_path is None:
            output_path = source_path.parent / f"{source_path.stem}_{target_format}"
        else:
            output_path = Path(output_path)

        # Log GPU memory before conversion if available
        if GPU_AUTOLOADER_AVAILABLE and memory_allocated and memory_reserved:
            try:
                initial_allocated = memory_allocated()
                initial_reserved = memory_reserved()
                logger.info(
                    f"GPU memory before conversion - Allocated: {initial_allocated / (1024**2):.1f}MB, Reserved: {initial_reserved / (1024**2):.1f}MB",
                )
            except Exception as e:
                logger.debug(f"Unable to get GPU memory stats: {e}")

        # Perform conversion
        converter_method = f"_convert_{source_format}_to_{target_format}"
        if hasattr(self, converter_method):
            try:
                result = getattr(self, converter_method)(source_path, output_path, **kwargs)

                # Clean up GPU memory after conversion
                if GPU_AUTOLOADER_AVAILABLE and empty_cache:
                    try:
                        empty_cache()
                        logger.debug("Cleared GPU cache after conversion")
                    except Exception as e:
                        logger.debug(f"Failed to clear GPU cache: {e}")

                # Log final GPU memory if available
                if GPU_AUTOLOADER_AVAILABLE and memory_allocated and memory_reserved:
                    try:
                        final_allocated = memory_allocated()
                        final_reserved = memory_reserved()
                        logger.info(
                            f"GPU memory after conversion - Allocated: {final_allocated / (1024**2):.1f}MB, Reserved: {final_reserved / (1024**2):.1f}MB",
                        )
                    except Exception as e:
                        logger.debug(f"Unable to get final GPU memory stats: {e}")

                return result
            except Exception as e:
                logger.error(f"Conversion failed: {e}")
                return None
        else:
            logger.error(f"Converter method {converter_method} not implemented")
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
            logger.error("ONNX not available for conversion")
            return None

        if not HAS_TORCH:
            logger.error("PyTorch not available for conversion")
            return None

        try:
            # Load PyTorch model
            if source_path.is_dir():
                # Load from Hugging Face format
                if HAS_TRANSFORMERS:
                    # Use unified GPU system for device selection
                    device = "cpu"
                    if GPU_AUTOLOADER_AVAILABLE:
                        device = get_device()
                    elif HAS_TORCH and torch.cuda.is_available():
                        device = "cuda"

                    model = AutoModelForCausalLM.from_pretrained(
                        str(source_path),
                        torch_dtype=torch.float32,
                        device_map=device if device != "cpu" else None,
                    )
                    config = AutoConfig.from_pretrained(str(source_path))

                    # Get model dimensions
                    batch_size = kwargs.get("batch_size", 1)
                    sequence_length = kwargs.get("sequence_length", 128)

                    # Create sample input tensor for model conversion
                    sample_input = torch.randint(
                        0,
                        config.vocab_size,
                        (batch_size, sequence_length),
                        dtype=torch.long,
                    )
                else:
                    logger.error("transformers required for loading HF models")
                    return None
            else:
                # Load standalone PyTorch model
                # Use unified GPU system for device selection
                device = "cpu"
                if GPU_AUTOLOADER_AVAILABLE:
                    device = get_device()
                elif HAS_TORCH and torch.cuda.is_available():
                    device = "cuda"

                model = torch.load(source_path, map_location=device)

                # Try to infer input shape
                input_shape = kwargs.get("input_shape")
                if not input_shape:
                    logger.error("input_shape required for standalone PyTorch models")
                    return None

                sample_input = torch.randn(*input_shape)

            # Set model to eval mode
            model.eval()

            # Move model to GPU if available for faster conversion
            if GPU_AUTOLOADER_AVAILABLE and to_device and device != "cpu":
                try:
                    model = to_device(model, device)
                    sample_input = to_device(sample_input, device)
                    logger.info(f"Model and inputs moved to {device} for conversion")
                except Exception as e:
                    logger.debug(f"Could not move to GPU, continuing on CPU: {e}")

            # Export to ONNX
            output_path.parent.mkdir(parents=True, exist_ok=True)

            # Dynamic axes for variable sequence length
            dynamic_axes = kwargs.get(
                "dynamic_axes",
                {
                    "input_ids": {0: "batch_size", 1: "sequence"},
                    "output": {0: "batch_size", 1: "sequence"},
                },
            )

            torch.onnx.export(
                model,
                sample_input,
                str(output_path),
                export_params=True,
                opset_version=kwargs.get("opset_version", 14),
                do_constant_folding=kwargs.get("do_constant_folding", True),
                input_names=kwargs.get("input_names", ["input_ids"]),
                output_names=kwargs.get("output_names", ["output"]),
                dynamic_axes=dynamic_axes,
                verbose=kwargs.get("verbose", False),
            )

            # Verify ONNX model
            onnx_model = onnx.load(str(output_path))
            onnx.checker.check_model(onnx_model)

            logger.info(f"Successfully converted PyTorch model to ONNX: {output_path}")
            return output_path

        except Exception as e:
            logger.error(f"Failed to convert PyTorch to ONNX: {e}")
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
        if not HAS_SAFETENSORS:
            logger.error("safetensors not available for conversion")
            return None

        try:
            # Load PyTorch model
            if source_path.is_dir():
                # Load state dict from directory
                model_files = list(source_path.glob("*.bin")) + list(source_path.glob("*.pt"))
                if not model_files:
                    logger.error("No PyTorch model files found")
                    return None

                state_dict = {}
                for model_file in model_files:
                    # Use unified GPU system for device selection
                    device = "cpu"
                    if GPU_AUTOLOADER_AVAILABLE:
                        device = get_device()
                    elif HAS_TORCH and torch.cuda.is_available():
                        device = "cuda"

                    state_dict |= torch.load(model_file, map_location=device)
            else:
                # Load single file
                # Use unified GPU system for device selection
                device = "cpu"
                if GPU_AUTOLOADER_AVAILABLE:
                    device = get_device()
                elif HAS_TORCH and torch.cuda.is_available():
                    device = "cuda"

                state_dict = torch.load(source_path, map_location=device)

                # Handle full model vs state dict
                if hasattr(state_dict, "state_dict"):
                    state_dict = state_dict.state_dict()

            # Ensure output directory exists
            output_path.parent.mkdir(parents=True, exist_ok=True)

            # Add .safetensors extension if needed
            if output_path.suffix != ".safetensors":
                output_path = output_path.with_suffix(".safetensors")

            # Apply GPU optimization if available before saving
            if GPU_AUTOLOADER_AVAILABLE and gpu_autoloader and device != "cpu":
                try:
                    # Try to optimize the state dict tensors
                    optimized_dict = {}
                    for key, tensor in state_dict.items():
                        if hasattr(tensor, "shape"):  # It's a tensor
                            optimized_tensor = gpu_autoloader(tensor)
                            optimized_dict[key] = optimized_tensor if optimized_tensor is not None else tensor
                        else:
                            optimized_dict[key] = tensor
                    state_dict = optimized_dict
                    logger.debug("Applied GPU optimizations to state dict before saving")
                except Exception as e:
                    logger.debug(f"Could not apply GPU optimizations: {e}")

            # Save to SafeTensors
            metadata = kwargs.get("metadata", {})
            save_file(state_dict, str(output_path), metadata=metadata)

            logger.info(f"Successfully converted PyTorch model to SafeTensors: {output_path}")
            return output_path

        except Exception as e:
            logger.error(f"Failed to convert PyTorch to SafeTensors: {e}")
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
        if not HAS_SAFETENSORS:
            logger.error("safetensors not available for conversion")
            return None

        try:
            # Extract conversion options from kwargs
            device = kwargs.get("device", "cpu")
            dtype = kwargs.get("dtype")
            preserve_layout = kwargs.get("preserve_layout", True)

            # Load SafeTensors
            state_dict = {}
            with safe_open(str(source_path), framework="pt", device=device) as f:
                for key in f:
                    tensor = f.get_tensor(key)
                    # Apply dtype conversion if specified
                    if dtype and hasattr(torch, dtype):
                        tensor = tensor.to(getattr(torch, dtype))
                    state_dict[key] = tensor

            # Ensure output directory exists
            output_path.parent.mkdir(parents=True, exist_ok=True)

            # Add .pt extension if needed
            if output_path.suffix not in [".pt", ".pth", ".bin"]:
                output_path = output_path.with_suffix(".pt")

            # Save as PyTorch with options
            save_kwargs = {}
            if not preserve_layout:
                save_kwargs["_use_new_zipfile_serialization"] = False
            torch.save(state_dict, str(output_path), **save_kwargs)

            logger.info(f"Successfully converted SafeTensors to PyTorch: {output_path}")
            return output_path

        except Exception as e:
            logger.error(f"Failed to convert SafeTensors to PyTorch: {e}")
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
        if not HAS_TF or not HAS_ONNX:
            logger.error("TensorFlow and ONNX required for conversion")
            return None

        try:
            # Try tf2onnx if available
            try:
                import tf2onnx

                # Load TensorFlow model
                if source_path.is_dir():
                    model = tf.saved_model.load(str(source_path))
                elif hasattr(tf, "keras"):
                    model = tf.keras.models.load_model(str(source_path))
                else:
                    raise ImportError("TensorFlow keras module not available")

                # Get concrete function
                if hasattr(model, "signatures"):
                    concrete_func = model.signatures[kwargs.get("signature_key", "serving_default")]
                else:
                    # For Keras models
                    input_spec = kwargs.get("input_spec")
                    if not input_spec:
                        logger.error("input_spec required for Keras models")
                        return None

                    @tf.function
                    def inference_func(x: object) -> object:
                        return model(x)

                    concrete_func = inference_func.get_concrete_function(input_spec)

                # Convert to ONNX
                output_path.parent.mkdir(parents=True, exist_ok=True)

                model_proto, _ = tf2onnx.convert.from_function(
                    concrete_func,
                    opset=kwargs.get("opset_version", 14),
                    output_path=str(output_path),
                )

                # Log model info
                if model_proto:
                    logger.info(f"Successfully converted TensorFlow model to ONNX: {output_path}")
                    logger.debug(f"ONNX model graph nodes: {len(model_proto.graph.node)}")
                else:
                    logger.warning("Model conversion completed but model_proto is None")

                return output_path

            except ImportError:
                logger.error("tf2onnx required for TensorFlow to ONNX conversion")
                return None

        except Exception as e:
            logger.error(f"Failed to convert TensorFlow to ONNX: {e}")
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
                logger.error("Could not detect model formats")
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
                    logger.error(f"Output key '{key}' missing in converted model")
                    return False

                # Numerical comparison
                diff = np.abs(original_output[key] - converted_output[key])
                max_diff = np.max(diff)

                if max_diff > tolerance:
                    logger.error(
                        f"Output mismatch for '{key}': max difference {max_diff} > {tolerance}",
                    )
                    return False

            logger.info("Conversion validation passed")
            return True

        except Exception as e:
            logger.error(f"Validation failed: {e}")
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
            if format == "onnx" and HAS_ONNX:
                # ONNX inference
                session = ort.InferenceSession(str(model_path))
                outputs = session.run(None, inputs)

                # Convert to dictionary
                output_names = [o.name for o in session.get_outputs()]
                return dict(zip(output_names, outputs, strict=False))

            if format == "pytorch":
                # PyTorch inference
                # Use unified GPU system for device selection
                device = "cpu"
                if GPU_AUTOLOADER_AVAILABLE:
                    device = get_device()
                elif HAS_TORCH and torch.cuda.is_available():
                    device = "cuda"

                model = torch.load(model_path, map_location=device)
                model.eval()

                with torch.no_grad():
                    # Convert inputs to torch tensors
                    torch_inputs = {k: torch.from_numpy(v) for k, v in inputs.items()}

                    # Move to device if available
                    if GPU_AUTOLOADER_AVAILABLE and to_device:
                        torch_inputs = {k: to_device(v) for k, v in torch_inputs.items()}
                        model = to_device(model)

                    # Run model
                    if isinstance(model, torch.nn.Module):
                        # Assume single input
                        output = model(torch_inputs["input"])
                    else:
                        output = model(**torch_inputs)

                    # Convert output to numpy
                    if isinstance(output, dict):
                        return {k: v.numpy() for k, v in output.items()}
                    return {"output": output.numpy()}

            elif format == "tensorflow" and HAS_TF:
                # TensorFlow inference
                model = tf.saved_model.load(str(model_path))

                # Get inference function
                infer = model.signatures.get("serving_default", model)

                # Run inference
                outputs = infer(**inputs)

                # Convert to numpy
                return {k: v.numpy() for k, v in outputs.items()}

            else:
                logger.error(f"Inference not supported for format: {format}")
                return None

        except Exception as e:
            logger.error(f"Inference failed: {e}")
            return None

    def get_model_info(self, model_path: Path) -> dict[str, Any]:
        """Get information about a model.

        Args:
            model_path: Path to model

        Returns:
            Dictionary with model information

        """
        info = {
            "path": str(model_path),
            "format": self._detect_format(model_path),
            "size_mb": 0,
            "parameters": {},
            "metadata": {},
        }

        # Get file size
        if model_path.is_file():
            info["size_mb"] = model_path.stat().st_size / (1024 * 1024)
        elif model_path.is_dir():
            total_size = sum(f.stat().st_size for f in model_path.rglob("*") if f.is_file())
            info["size_mb"] = total_size / (1024 * 1024)

        # Format-specific info
        if info["format"] == "onnx" and HAS_ONNX:
            try:
                model = onnx.load(str(model_path))
                info["parameters"]["inputs"] = [
                    {
                        "name": i.name,
                        "shape": [d.dim_value for d in i.type.tensor_type.shape.dim],
                    }
                    for i in model.graph.input
                ]
                info["parameters"]["outputs"] = [
                    {
                        "name": o.name,
                        "shape": [d.dim_value for d in o.type.tensor_type.shape.dim],
                    }
                    for o in model.graph.output
                ]
                info["metadata"]["opset_version"] = model.opset_import[0].version
            except Exception as e:
                logger.debug(f"Could not get ONNX model metadata: {e}")

        return info

    def load_model_for_conversion(self, model_path: str | Path, model_type: str = "auto") -> object | None:
        """Load a model using appropriate AutoModel class based on type.

        Args:
            model_path: Path to model
            model_type: Type of model (auto, base, causal_lm, seq2seq, classification, etc.)

        Returns:
            Loaded model or None

        """
        if not HAS_TRANSFORMERS or not AutoModel:
            logger.error("transformers with AutoModel required")
            return None

        try:
            model_path = Path(model_path)

            # Map model types to appropriate AutoModel classes
            model_loaders = {
                "auto": AutoModel,
                "base": AutoModel,
                "causal_lm": AutoModelForCausalLM,
                "seq2seq": lambda path: AutoModel.from_pretrained(path, trust_remote_code=True),
                "classification": lambda path: AutoModel.from_pretrained(path, num_labels=2),
                "token_classification": lambda path: AutoModel.from_pretrained(path, num_labels=9),
                "question_answering": lambda path: AutoModel.from_pretrained(path),
                "feature_extraction": AutoModel,
            }

            # Get the appropriate loader
            loader = model_loaders.get(model_type, AutoModel)

            # Load the model
            if callable(loader) and hasattr(loader, "from_pretrained"):
                model = loader.from_pretrained(str(model_path))
            elif callable(loader):
                model = loader(str(model_path))
            else:
                model = AutoModel.from_pretrained(str(model_path))

            logger.info(f"Successfully loaded model from {model_path} as {model_type}")
            return model

        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            return None

    def analyze_model_architecture(self, model_path: str | Path) -> dict[str, Any] | None:
        """Analyze model architecture using AutoModel to determine conversion requirements.

        Args:
            model_path: Path to model

        Returns:
            Dictionary with architecture details or None

        """
        if not HAS_TRANSFORMERS or not AutoModel:
            logger.error("transformers with AutoModel required")
            return None

        try:
            # First try to load config
            config = AutoConfig.from_pretrained(str(model_path))

            # Try to load with AutoModel to get architecture info
            model = AutoModel.from_pretrained(
                str(model_path),
                output_loading_info=True,
            )

            # Get model info
            architecture_info = {
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

            # Clean up
            del model
            if GPU_AUTOLOADER_AVAILABLE and empty_cache:
                empty_cache()
            elif HAS_TORCH and torch.cuda.is_available():
                torch.cuda.empty_cache()

            return architecture_info

        except Exception as e:
            logger.error(f"Failed to analyze model architecture: {e}")
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
        # Load model with AutoModel
        model = self.load_model_for_conversion(source_path, model_type)
        if model is None:
            return None

        output_path = kwargs.get("output_path", Path(source_path).parent / f"{Path(source_path).stem}_{target_format}")

        try:
            if target_format == "onnx" and HAS_ONNX and HAS_TORCH:
                # Convert to ONNX
                model.eval()

                # Get input dimensions
                config = AutoConfig.from_pretrained(str(source_path))
                batch_size = kwargs.get("batch_size", 1)
                seq_length = kwargs.get("sequence_length", 128)

                # Create appropriate sample input tensor based on model type
                if hasattr(config, "vocab_size"):
                    sample_input = torch.randint(0, config.vocab_size, (batch_size, seq_length))
                else:
                    # For non-text models
                    input_shape = kwargs.get("input_shape", (batch_size, 3, 224, 224))
                    sample_input = torch.randn(*input_shape)

                # Export
                torch.onnx.export(
                    model,
                    sample_input,
                    str(output_path),
                    export_params=True,
                    opset_version=kwargs.get("opset_version", 14),
                    input_names=kwargs.get("input_names", ["input"]),
                    output_names=kwargs.get("output_names", ["output"]),
                    dynamic_axes=kwargs.get("dynamic_axes", {"input": {0: "batch_size"}, "output": {0: "batch_size"}}),
                )

                logger.info(f"Successfully converted model to {target_format} using AutoModel")
                return output_path

            logger.error(f"Conversion to {target_format} not supported with AutoModel method")
            return None

        except Exception as e:
            logger.error(f"Failed to convert model with AutoModel: {e}")
            return None
        finally:
            # Clean up
            del model
            if GPU_AUTOLOADER_AVAILABLE and empty_cache:
                empty_cache()
            elif HAS_TORCH and torch.cuda.is_available():
                torch.cuda.empty_cache()


# Global instance
_CONVERTER = None


def get_model_converter() -> ModelFormatConverter:
    """Get the global model format converter."""
    global _CONVERTER
    if _CONVERTER is None:
        _CONVERTER = ModelFormatConverter()
    return _CONVERTER
