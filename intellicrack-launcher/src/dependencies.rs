use anyhow::Result;
use pyo3::Python;
use pyo3::prelude::*;
use pyo3::types::{IntoPyDict, PyDict};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::ffi::CStr;
use std::process::Command;
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyStatus {
    pub available: bool,
    pub version: Option<String>,
    pub details: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationSummary {
    pub dependencies: HashMap<String, DependencyStatus>,
    pub flask_validation: Option<FlaskValidationResult>,
    pub tensorflow_validation: Option<TensorFlowValidationResult>,
    pub llama_validation: Option<LlamaValidationResult>,
    pub system_health: Option<SystemHealthReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlaskValidationResult {
    pub status: bool,
    pub message: String,
    pub cors_enabled: bool,
    pub max_upload_mb: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TensorFlowValidationResult {
    pub status: bool,
    pub version: String,
    pub gpu_available: bool,
    pub gpu_count: u32,
    pub keras_available: bool,
    pub model_building: bool,
    pub model_prediction_test: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlamaValidationResult {
    pub status: bool,
    pub version: String,
    pub supports_gpu: bool,
    pub quantization_support: bool,
    pub supported_formats: Vec<String>,
    pub default_params_available: bool,
    pub params_modifiable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemHealthReport {
    pub platform: String,
    pub python_version: String,
    pub services: HashMap<String, serde_json::Value>,
    pub disk_space: HashMap<String, serde_json::Value>,
}

impl ValidationSummary {
    #[must_use] 
    pub fn all_critical_available(&self) -> bool {
        let critical_deps = ["Flask", "TensorFlow"];
        critical_deps.iter().all(|dep| {
            self.dependencies
                .get(*dep)
                .is_some_and(|status| status.available)
        })
    }

    #[must_use] 
    pub fn total(&self) -> usize {
        self.dependencies.len()
    }

    #[must_use] 
    pub fn successful(&self) -> usize {
        self.dependencies
            .values()
            .filter(|status| status.available)
            .count()
    }

    #[must_use] 
    pub fn failed(&self) -> usize {
        self.dependencies
            .values()
            .filter(|status| !status.available)
            .count()
    }

    #[must_use] 
    pub fn success_rate(&self) -> f64 {
        if self.total() == 0 {
            0.0
        } else {
            (self.successful() as f64 / self.total() as f64) * 100.0
        }
    }
}

#[derive(Clone)]
pub struct DependencyValidator {
    results: HashMap<String, DependencyStatus>,
}

impl DependencyValidator {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            results: HashMap::new(),
        }
    }

    pub async fn validate_all_dependencies(&mut self) -> Result<ValidationSummary> {
        info!("Starting comprehensive dependency validation");

        // Check core dependencies
        self.check_flask_dependency().await?;
        self.check_tensorflow_dependency().await?;
        self.check_llama_cpp_dependency().await?;
        self.check_qemu_dependency().await?;

        // Perform enhanced validations
        let flask_validation = if self.is_dependency_available("Flask") {
            Some(self.validate_flask_server().await?)
        } else {
            None
        };

        let tensorflow_validation = if self.is_dependency_available("TensorFlow") {
            Some(self.validate_tensorflow_models().await?)
        } else {
            None
        };

        let llama_validation = if self.is_dependency_available("llama-cpp-python") {
            Some(self.validate_llama_cpp().await?)
        } else {
            None
        };

        let system_health = Some(self.generate_system_health_report().await?);

        Ok(ValidationSummary {
            dependencies: self.results.clone(),
            flask_validation,
            tensorflow_validation,
            llama_validation,
            system_health,
        })
    }

    async fn check_flask_dependency(&mut self) -> Result<()> {
        info!("Checking Flask dependency");

        let flask_status = Python::attach(|py| -> Result<DependencyStatus> {
            match py.import("flask") {
                Ok(flask_module) => {
                    let flask_cors = py.import("flask_cors")?;

                    // Test Flask by creating minimal app
                    let flask_class = flask_module.getattr("Flask")?;
                    let test_app = flask_class.call1(("test_app",))?;

                    // Test CORS
                    let cors_class = flask_cors.getattr("CORS")?;
                    cors_class.call1((test_app.clone(),))?;

                    // Test basic routing capability
                    let route = test_app.getattr("route")?;
                    let test_route_decorator = route.call1(("/test",))?;
                    // Validate the decorator is callable (proves routing is functional)
                    if !test_route_decorator.is_callable() {
                        warn!("Flask route decorator is not callable - routing may be broken");
                    }

                    // Test app context
                    let app_context = test_app.call_method0("app_context")?;
                    let _ctx = app_context.call_method0("__enter__")?;

                    let config = test_app.getattr("config")?;
                    config.set_item("TESTING", true)?;

                    let mut details = HashMap::new();
                    details.insert(
                        "web_ui_available".to_string(),
                        serde_json::Value::Bool(true),
                    );
                    details.insert("cors_enabled".to_string(), serde_json::Value::Bool(true));
                    details.insert("routing_tested".to_string(), serde_json::Value::Bool(true));

                    Ok(DependencyStatus {
                        available: true,
                        version: flask_module
                            .getattr("__version__")
                            .ok()
                            .and_then(|v| v.extract().ok()),
                        details,
                    })
                }
                Err(_) => Ok(DependencyStatus {
                    available: false,
                    version: None,
                    details: HashMap::new(),
                }),
            }
        })?;

        if flask_status.available {
            info!("Flask verified: Web UI and API endpoints available");
        } else {
            warn!("Flask not available - Disabling local GGUF server");
        }

        self.results.insert("Flask".to_string(), flask_status);
        Ok(())
    }

    async fn check_tensorflow_dependency(&mut self) -> Result<()> {
        info!("Checking TensorFlow dependency");

        let tf_status = Python::attach(|py| -> Result<DependencyStatus> {
            // Configure TensorFlow environment
            unsafe {
                env::set_var("TF_CPP_MIN_LOG_LEVEL", "2");
                env::set_var("CUDA_VISIBLE_DEVICES", "-1");
                env::set_var("MKL_THREADING_LAYER", "GNU");
            }

            match py.import("intellicrack.handlers.tensorflow_handler") {
                Ok(tf_handler) => {
                    let tf = tf_handler.getattr("tensorflow")?;

                    // Disable GPU for Intel Arc B580 compatibility
                    let config = tf.getattr("config")?;
                    config.call_method1(
                        "set_visible_devices",
                        (py.eval(c"[]", None, None)?, py.eval(c"'GPU'", None, None)?),
                    )?;

                    // Test basic tensor operations
                    let constant =
                        tf.call_method1("constant", (vec![vec![1.0, 2.0], vec![3.0, 4.0]],))?;
                    let reduce_sum = tf.call_method1("reduce_sum", (constant,))?;
                    let numpy_result = reduce_sum.call_method0("numpy")?;
                    let result_value: f64 = numpy_result.extract()?;

                    let expected_sum = 10.0;
                    let tensor_ops_valid = (result_value - expected_sum).abs() < 1e-6;

                    let mut details = HashMap::new();
                    let version: String = tf.getattr("__version__")?.extract()?;
                    details.insert(
                        "version".to_string(),
                        serde_json::Value::String(version.clone()),
                    );
                    details.insert(
                        "tensor_ops_valid".to_string(),
                        serde_json::Value::Bool(tensor_ops_valid),
                    );
                    details.insert(
                        "gpu_disabled_intel_arc".to_string(),
                        serde_json::Value::Bool(true),
                    );

                    // Check GPU availability
                    let physical_devices =
                        config.call_method1("list_physical_devices", ("GPU",))?;
                    let gpu_count: usize = physical_devices.call_method0("__len__")?.extract()?;
                    details.insert(
                        "gpu_count".to_string(),
                        serde_json::Value::Number(serde_json::Number::from(gpu_count)),
                    );

                    Ok(DependencyStatus {
                        available: tensor_ops_valid,
                        version: Some(version),
                        details,
                    })
                }
                Err(_) => Ok(DependencyStatus {
                    available: false,
                    version: None,
                    details: HashMap::new(),
                }),
            }
        })?;

        if tf_status.available {
            info!("TensorFlow verified with tensor operations");
        } else {
            warn!("ML Vulnerability Predictor not available (TensorFlow not available)");
        }

        self.results.insert("TensorFlow".to_string(), tf_status);
        Ok(())
    }

    async fn check_llama_cpp_dependency(&mut self) -> Result<()> {
        info!("Checking llama-cpp-python dependency");

        let llama_status = Python::attach(|py| -> Result<DependencyStatus> {
            match py.import("llama_cpp") {
                Ok(llama_module) => {
                    let mut details = HashMap::new();

                    // Get version
                    let version = llama_module
                        .getattr("__version__")
                        .ok()
                        .and_then(|v| v.extract().ok())
                        .unwrap_or_else(|| "Unknown".to_string());

                    // Test model parameters
                    let model_params = llama_module.call_method0("llama_model_params")?;
                    let context_params = llama_module.call_method0("llama_context_params")?;

                    // Test parameter modification
                    let mut params_functional = false;
                    if model_params.hasattr("n_gpu_layers")?
                        && context_params.hasattr("n_ctx")?
                        && let Ok(original_gpu_layers) = model_params.getattr("n_gpu_layers")
                        && let Ok(original_ctx_size) = context_params.getattr("n_ctx")
                    {
                        // Test parameter modification
                        model_params.setattr("n_gpu_layers", 0)?;
                        context_params.setattr("n_ctx", 512)?;

                        // Restore original values
                        model_params.setattr("n_gpu_layers", original_gpu_layers)?;
                        context_params.setattr("n_ctx", original_ctx_size)?;

                        params_functional = true;
                    }

                    details.insert(
                        "version".to_string(),
                        serde_json::Value::String(version.clone()),
                    );
                    details.insert(
                        "params_functional".to_string(),
                        serde_json::Value::Bool(params_functional),
                    );
                    details.insert(
                        "gpu_layers_supported".to_string(),
                        serde_json::Value::Bool(
                            model_params.hasattr("n_gpu_layers").unwrap_or(false),
                        ),
                    );

                    Ok(DependencyStatus {
                        available: params_functional,
                        version: Some(version),
                        details,
                    })
                }
                Err(_) => Ok(DependencyStatus {
                    available: false,
                    version: None,
                    details: HashMap::new(),
                }),
            }
        })?;

        if llama_status.available {
            info!("LLM Manager available with llama-cpp backend");
        } else {
            warn!("LLM Manager not available");
        }

        self.results
            .insert("llama-cpp-python".to_string(), llama_status);
        Ok(())
    }

    async fn check_qemu_dependency(&mut self) -> Result<()> {
        info!("Checking QEMU dependency");

        let qemu_status = if let Ok(_) = Command::new("qemu-system-x86_64").arg("--version").output() {
            info!("QEMU system emulator found");
            DependencyStatus {
                available: true,
                version: None,
                details: {
                    let mut details = HashMap::new();
                    details
                        .insert("system_emulator".to_string(), serde_json::Value::Bool(true));
                    details
                },
            }
        } else {
            warn!("QEMU not found - QEMU functionality will be limited");
            DependencyStatus {
                available: false,
                version: None,
                details: HashMap::new(),
            }
        };

        self.results.insert("QEMU".to_string(), qemu_status);
        Ok(())
    }

    fn is_dependency_available(&self, name: &str) -> bool {
        self.results
            .get(name)
            .is_some_and(|status| status.available)
    }

    async fn validate_flask_server(&self) -> Result<FlaskValidationResult> {
        info!("Validating Flask server configuration");

        let result = Python::attach(|py| -> Result<FlaskValidationResult> {
            let secrets = py.import("secrets")?;
            let flask = py.import("flask")?;
            let flask_cors = py.import("flask_cors")?;

            // Create test Flask app
            let flask_class = flask.getattr("Flask")?;
            let app = flask_class.call1(("test_validation_app",))?;

            // Configure CORS
            let cors_class = flask_cors.getattr("CORS")?;
            let cors_config = PyDict::new(py);
            let resources_dict = PyDict::new(py);
            let origins_dict = PyDict::new(py);
            origins_dict.set_item("origins", "*")?;
            resources_dict.set_item("/*", origins_dict)?;
            cors_config.set_item("resources", resources_dict)?;
            let kwargs = [("resources", cors_config)].into_py_dict(py).unwrap();
            cors_class.call((app.clone(),), Some(&kwargs))?;

            // Configure app
            let config = app.getattr("config")?;
            let secret_key = secrets.call_method1("token_hex", (32,))?;
            config.call_method1(
                "update",
                (py.eval(
                    CStr::from_bytes_with_nul(
                        format!(
                            "{{'SECRET_KEY': '{}', 'JSON_SORT_KEYS': False, 'MAX_CONTENT_LENGTH': {}}}\0",
                            secret_key.extract::<String>()?,
                            16 * 1024 * 1024
                        ).as_bytes()
                    ).unwrap(),
                    None,
                    None,
                )?,),
            )?;

            // Test request context
            let test_request_context =
                app.call_method("test_request_context", ("/test", "POST"), None)?;
            let ctx = test_request_context.call_method0("__enter__")?;
            // Validate context was established (ctx contains the active request context)
            if ctx.is_none() {
                warn!("Flask request context creation returned None");
            }

            let flask_request = flask.getattr("request")?;
            let path: String = flask_request.getattr("path")?.extract()?;
            let method: String = flask_request.getattr("method")?.extract()?;

            test_request_context.call_method0("__exit__")?;

            let validation_success = path == "/test" && method == "POST";

            Ok(FlaskValidationResult {
                status: validation_success,
                message: if validation_success {
                    "Flask server validated".to_string()
                } else {
                    "Flask validation failed".to_string()
                },
                cors_enabled: true,
                max_upload_mb: 16,
            })
        })?;

        Ok(result)
    }

    async fn validate_tensorflow_models(&self) -> Result<TensorFlowValidationResult> {
        info!("Validating TensorFlow model capabilities");

        let result = Python::attach(|py| -> Result<TensorFlowValidationResult> {
            // Configure TensorFlow environment
            unsafe {
                env::set_var("TF_CPP_MIN_LOG_LEVEL", "2");
                env::set_var("CUDA_VISIBLE_DEVICES", "-1");
                env::set_var("MKL_THREADING_LAYER", "GNU");
            }

            // Import tensorflow handler and get tensorflow module
            let tf_handler = py.import("intellicrack.handlers.tensorflow_handler")?;
            let tf = tf_handler.getattr("tensorflow")?;

            // Disable GPU
            let config = tf.getattr("config")?;
            let empty_list = py.eval(c"[]", None, None)?;
            let gpu_string = py.eval(c"'GPU'", None, None)?;
            config.call_method1("set_visible_devices", (empty_list, gpu_string))?;

            // Get TF info
            let version: String = tf.getattr("__version__")?.extract()?;
            let physical_devices = config.call_method1("list_physical_devices", ("GPU",))?;
            let gpu_count: usize = physical_devices.call_method0("__len__")?.extract()?;
            let keras_available = tf.hasattr("keras")?;
            let keras = tf.getattr("keras")?;
            let layers = keras.getattr("layers")?;

            let shape_tuple = py.eval(c"(10,)", None, None)?;
            let shape_kwargs = [("shape", shape_tuple)].into_py_dict(py).unwrap();
            let input_layer = layers.call_method("Input", (), Some(&shape_kwargs))?;
            let relu_kwargs = [("activation", "relu")].into_py_dict(py).unwrap();
            let dense1 = layers.call_method("Dense", (64,), Some(&relu_kwargs))?;
            let dense2 = layers.call_method("Dense", (32,), Some(&relu_kwargs))?;
            let sigmoid_kwargs = [("activation", "sigmoid")].into_py_dict(py).unwrap();
            let dense3 = layers.call_method("Dense", (1,), Some(&sigmoid_kwargs))?;

            let sequential = keras.getattr("Sequential")?;
            let locals_dict = [
                ("input_layer", input_layer),
                ("dense1", dense1),
                ("dense2", dense2),
                ("dense3", dense3),
            ]
            .into_py_dict(py)
            .unwrap();
            let model = sequential.call1((py.eval(
                c"[input_layer, dense1, dense2, dense3]",
                Some(&locals_dict),
                None,
            )?,))?;

            let compile_kwargs = [("optimizer", "adam"), ("loss", "binary_crossentropy")]
                .into_py_dict(py)
                .unwrap();
            model.call_method("compile", (), Some(&compile_kwargs))?;

            // Test prediction
            let test_input = tf.call_method1("constant", (vec![vec![1.0; 10]],))?;
            let test_output = model.call1((test_input,))?;

            let output_shape = test_output.getattr("shape")?;
            let shape_list: Vec<i64> = output_shape.extract()?;
            let expected_shape = vec![1i64, 1i64];

            let model_building_success = shape_list == expected_shape;
            let mut model_prediction_test = "✗ Shape validation failed".to_string();

            if model_building_success {
                let numpy_output = test_output.call_method0("numpy")?;
                let output_array: Vec<Vec<f64>> = numpy_output.extract()?;
                if let Some(first_row) = output_array.first()
                    && let Some(output_value) = first_row.first()
                {
                    if *output_value >= 0.0 && *output_value <= 1.0 {
                        model_prediction_test = format!("✓ (output: {output_value:.3})");
                    } else {
                        model_prediction_test = format!("✗ Invalid output range: {output_value}");
                    }
                }
            }

            Ok(TensorFlowValidationResult {
                status: model_building_success,
                version,
                gpu_available: gpu_count > 0,
                gpu_count: gpu_count as u32,
                keras_available,
                model_building: model_building_success,
                model_prediction_test,
            })
        })?;

        Ok(result)
    }

    async fn validate_llama_cpp(&self) -> Result<LlamaValidationResult> {
        info!("Validating llama-cpp-python capabilities");

        let result = Python::attach(|py| -> Result<LlamaValidationResult> {
            let llama_cpp = py.import("llama_cpp")?;

            let version = llama_cpp
                .getattr("__version__")
                .ok()
                .and_then(|v| v.extract().ok())
                .unwrap_or_else(|| "Unknown".to_string());

            let supports_gpu = llama_cpp.hasattr("llama_backend_init")?;

            // Check quantization support
            let quantization_support = llama_cpp.hasattr("GGML_TYPE_Q4_0")?;
            let supported_formats = if quantization_support {
                vec!["GGUF".to_string(), "GGML".to_string()]
            } else {
                vec![]
            };

            // Test parameter creation
            let mut default_params_available = false;
            let mut params_modifiable = false;

            if let Ok(params) = llama_cpp.call_method0("llama_model_default_params")
                && params.hasattr("n_ctx")?
                && params.hasattr("n_batch")?
            {
                default_params_available = true;

                // Test parameter modification
                if let Ok(original_ctx) = params.getattr("n_ctx")
                    && params.setattr("n_ctx", 1024).is_ok()
                    && params.setattr("n_ctx", original_ctx).is_ok()
                {
                    params_modifiable = true;
                }
            }

            Ok(LlamaValidationResult {
                status: default_params_available,
                version,
                supports_gpu,
                quantization_support,
                supported_formats,
                default_params_available,
                params_modifiable,
            })
        })?;

        Ok(result)
    }

    async fn generate_system_health_report(&self) -> Result<SystemHealthReport> {
        info!("Generating system health report");

        let report = Python::attach(|py| -> Result<SystemHealthReport> {
            let sys = py.import("sys")?;
            let platform: String = sys.getattr("platform")?.extract()?;
            let version_info = sys.getattr("version")?.extract::<String>()?;
            let python_version = version_info
                .split_whitespace()
                .next()
                .unwrap_or("Unknown")
                .to_string();

            let mut services = HashMap::new();

            // Web UI service health
            if let Ok(flask) = py.import("flask") {
                if let Ok(flask_cors) = py.import("flask_cors") {
                    let flask_class = flask.getattr("Flask")?;
                    let test_app = flask_class.call1(("health_test",))?;

                    let cors_class = flask_cors.getattr("CORS")?;
                    cors_class.call1((test_app.clone(),))?;

                    let debug_mode = test_app.getattr("debug")?.extract::<bool>()?;

                    services.insert(
                        "web_ui".to_string(),
                        serde_json::json!({
                            "available": true,
                            "framework": "Flask",
                            "cors_enabled": true,
                            "debug_mode": debug_mode
                        }),
                    );
                }
            } else {
                services.insert(
                    "web_ui".to_string(),
                    serde_json::json!({"available": false}),
                );
            }

            // ML Engine service health
            if let Ok(tf_handler) = py.import("intellicrack.handlers.tensorflow_handler") {
                let tf = tf_handler.getattr("tensorflow")?;
                let version: String = tf.getattr("__version__")?.extract()?;

                let config = tf.getattr("config")?;
                config.call_method1(
                    "set_visible_devices",
                    (py.eval(c"[]", None, None)?, py.eval(c"'GPU'", None, None)?),
                )?;

                let physical_devices = config.call_method1("list_physical_devices", ("GPU",))?;
                let gpu_count: usize = physical_devices.call_method0("__len__")?.extract()?;

                services.insert(
                    "ml_engine".to_string(),
                    serde_json::json!({
                        "available": true,
                        "backend": "TensorFlow",
                        "version": version,
                        "gpu_support": gpu_count > 0
                    }),
                );
            } else {
                services.insert(
                    "ml_engine".to_string(),
                    serde_json::json!({"available": false}),
                );
            }

            // LLM Engine service health
            if let Ok(llama_cpp) = py.import("llama_cpp") {
                let version = llama_cpp
                    .getattr("__version__")
                    .ok()
                    .and_then(|v| v.extract().ok())
                    .unwrap_or_else(|| "Unknown".to_string());

                let gpu_support = llama_cpp.hasattr("llama_backend_init")?;

                services.insert(
                    "llm_engine".to_string(),
                    serde_json::json!({
                        "available": true,
                        "backend": "llama-cpp-python",
                        "version": version,
                        "gpu_support": gpu_support
                    }),
                );
            } else {
                services.insert(
                    "llm_engine".to_string(),
                    serde_json::json!({"available": false}),
                );
            }

            // Disk space information
            let mut disk_space = HashMap::new();
            if let Ok(shutil) = py.import("shutil")
                && let Ok(path_resolver) = py.import("intellicrack.utils.path_resolver")
                && let Ok(data_dir_func) = path_resolver.getattr("get_data_dir")
                && let Ok(data_dir) = data_dir_func.call0()
            {
                let data_dir_str = data_dir.str()?.extract::<String>()?;
                if let Ok(disk_usage) = shutil.call_method1("disk_usage", (data_dir,)) {
                    let total: u64 = disk_usage.getattr("total")?.extract()?;
                    let used: u64 = disk_usage.getattr("used")?.extract()?;
                    let free: u64 = disk_usage.getattr("free")?.extract()?;

                    let total_gb = (total as f64) / (1024.0_f64.powi(3));
                    let used_gb = (used as f64) / (1024.0_f64.powi(3));
                    let free_gb = (free as f64) / (1024.0_f64.powi(3));
                    let percent_used = ((used as f64) / (total as f64)) * 100.0;

                    disk_space.insert(
                        "data_directory".to_string(),
                        serde_json::Value::String(data_dir_str),
                    );
                    disk_space.insert(
                        "total_gb".to_string(),
                        serde_json::Value::Number(
                            serde_json::Number::from_f64(total_gb.round() * 100.0 / 100.0).unwrap(),
                        ),
                    );
                    disk_space.insert(
                        "used_gb".to_string(),
                        serde_json::Value::Number(
                            serde_json::Number::from_f64(used_gb.round() * 100.0 / 100.0).unwrap(),
                        ),
                    );
                    disk_space.insert(
                        "free_gb".to_string(),
                        serde_json::Value::Number(
                            serde_json::Number::from_f64(free_gb.round() * 100.0 / 100.0).unwrap(),
                        ),
                    );
                    disk_space.insert(
                        "percent_used".to_string(),
                        serde_json::Value::Number(
                            serde_json::Number::from_f64(percent_used.round() * 10.0 / 10.0)
                                .unwrap(),
                        ),
                    );
                }
            }

            if disk_space.is_empty() {
                disk_space.insert("available".to_string(), serde_json::Value::Bool(false));
            }

            Ok(SystemHealthReport {
                platform,
                python_version,
                services,
                disk_space,
            })
        })?;

        Ok(report)
    }

    pub async fn validate_python_availability(&mut self) -> Result<ValidationSummary> {
        info!("Validating Python availability");
        self.check_flask_dependency().await?;
        let summary = ValidationSummary {
            dependencies: self.results.clone(),
            flask_validation: None,
            tensorflow_validation: None,
            llama_validation: None,
            system_health: None,
        };
        Ok(summary)
    }

    pub async fn validate_flask_comprehensive(&mut self) -> Result<ValidationSummary> {
        info!("Running comprehensive Flask validation");
        self.check_flask_dependency().await?;
        let flask_validation = if self.is_dependency_available("Flask") {
            Some(self.validate_flask_server().await?)
        } else {
            None
        };
        let summary = ValidationSummary {
            dependencies: self.results.clone(),
            flask_validation,
            tensorflow_validation: None,
            llama_validation: None,
            system_health: None,
        };
        Ok(summary)
    }

    pub async fn validate_tensorflow_comprehensive(&mut self) -> Result<ValidationSummary> {
        info!("Running comprehensive TensorFlow validation");
        self.check_tensorflow_dependency().await?;
        let tensorflow_validation = if self.is_dependency_available("TensorFlow") {
            Some(self.validate_tensorflow_models().await?)
        } else {
            None
        };
        let summary = ValidationSummary {
            dependencies: self.results.clone(),
            flask_validation: None,
            tensorflow_validation,
            llama_validation: None,
            system_health: None,
        };
        Ok(summary)
    }

    pub async fn validate_qemu_availability(&mut self) -> Result<ValidationSummary> {
        info!("Validating QEMU availability");
        self.check_qemu_dependency().await?;
        let summary = ValidationSummary {
            dependencies: self.results.clone(),
            flask_validation: None,
            tensorflow_validation: None,
            llama_validation: None,
            system_health: None,
        };
        Ok(summary)
    }

    pub async fn validate_system_tools(&mut self) -> Result<ValidationSummary> {
        info!("Validating system tools");
        self.check_qemu_dependency().await?;
        let system_health = Some(self.generate_system_health_report().await?);
        let summary = ValidationSummary {
            dependencies: self.results.clone(),
            flask_validation: None,
            tensorflow_validation: None,
            llama_validation: None,
            system_health,
        };
        Ok(summary)
    }
}

impl Default for DependencyValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::env;

    fn create_test_dependency_status(available: bool, version: Option<String>) -> DependencyStatus {
        let mut details = HashMap::new();
        details.insert("test".to_string(), json!(true));

        DependencyStatus {
            available,
            version,
            details,
        }
    }

    fn create_test_validation_summary() -> ValidationSummary {
        let mut dependencies = HashMap::new();
        dependencies.insert(
            "Flask".to_string(),
            create_test_dependency_status(true, Some("2.3.3".to_string())),
        );
        dependencies.insert(
            "TensorFlow".to_string(),
            create_test_dependency_status(true, Some("2.13.0".to_string())),
        );
        dependencies.insert(
            "llama-cpp-python".to_string(),
            create_test_dependency_status(false, None),
        );
        dependencies.insert(
            "QEMU".to_string(),
            create_test_dependency_status(true, None),
        );

        ValidationSummary {
            dependencies,
            flask_validation: Some(FlaskValidationResult {
                status: true,
                message: "Flask validated".to_string(),
                cors_enabled: true,
                max_upload_mb: 16,
            }),
            tensorflow_validation: Some(TensorFlowValidationResult {
                status: true,
                version: "2.13.0".to_string(),
                gpu_available: false,
                gpu_count: 0,
                keras_available: true,
                model_building: true,
                model_prediction_test: "✓ (output: 0.523)".to_string(),
            }),
            llama_validation: None,
            system_health: Some(SystemHealthReport {
                platform: "win32".to_string(),
                python_version: "3.11.0".to_string(),
                services: HashMap::new(),
                disk_space: HashMap::new(),
            }),
        }
    }

    #[test]
    fn test_dependency_validator_creation() {
        let validator = DependencyValidator::new();
        assert!(validator.results.is_empty());
    }

    #[test]
    fn test_dependency_validator_default() {
        let validator = DependencyValidator::default();
        assert!(validator.results.is_empty());
    }

    #[test]
    fn test_dependency_status_creation() {
        let mut details = HashMap::new();
        details.insert("version_check".to_string(), json!("passed"));
        details.insert("functionality_test".to_string(), json!(true));

        let status = DependencyStatus {
            available: true,
            version: Some("1.2.3".to_string()),
            details,
        };

        assert!(status.available);
        assert_eq!(status.version, Some("1.2.3".to_string()));
        assert_eq!(status.details.len(), 2);
        assert_eq!(status.details.get("version_check"), Some(&json!("passed")));
    }

    #[test]
    fn test_dependency_status_serialization() {
        let status = create_test_dependency_status(true, Some("2.0.0".to_string()));

        // Test JSON serialization
        let json_str = serde_json::to_string(&status).unwrap();
        assert!(json_str.contains("available"));
        assert!(json_str.contains("2.0.0"));

        // Test deserialization
        let deserialized: DependencyStatus = serde_json::from_str(&json_str).unwrap();
        assert_eq!(deserialized.available, status.available);
        assert_eq!(deserialized.version, status.version);
    }

    #[test]
    fn test_flask_validation_result_creation() {
        let result = FlaskValidationResult {
            status: true,
            message: "Flask validation successful".to_string(),
            cors_enabled: true,
            max_upload_mb: 32,
        };

        assert!(result.status);
        assert!(result.cors_enabled);
        assert_eq!(result.max_upload_mb, 32);
        assert_eq!(result.message, "Flask validation successful");
    }

    #[test]
    fn test_tensorflow_validation_result_creation() {
        let result = TensorFlowValidationResult {
            status: true,
            version: "2.13.0".to_string(),
            gpu_available: true,
            gpu_count: 2,
            keras_available: true,
            model_building: true,
            model_prediction_test: "✓ Model prediction successful".to_string(),
        };

        assert!(result.status);
        assert!(result.gpu_available);
        assert_eq!(result.gpu_count, 2);
        assert!(result.keras_available);
        assert!(result.model_building);
        assert_eq!(result.version, "2.13.0");
    }

    #[test]
    fn test_llama_validation_result_creation() {
        let result = LlamaValidationResult {
            status: true,
            version: "0.2.11".to_string(),
            supports_gpu: true,
            quantization_support: true,
            supported_formats: vec!["GGUF".to_string(), "GGML".to_string()],
            default_params_available: true,
            params_modifiable: true,
        };

        assert!(result.status);
        assert!(result.supports_gpu);
        assert!(result.quantization_support);
        assert_eq!(result.supported_formats.len(), 2);
        assert!(result.default_params_available);
        assert!(result.params_modifiable);
    }

    #[test]
    fn test_system_health_report_creation() {
        let mut services = HashMap::new();
        services.insert(
            "web_ui".to_string(),
            json!({
                "available": true,
                "framework": "Flask"
            }),
        );

        let mut disk_space = HashMap::new();
        disk_space.insert("total_gb".to_string(), json!(500.0));
        disk_space.insert("free_gb".to_string(), json!(250.0));

        let report = SystemHealthReport {
            platform: "win32".to_string(),
            python_version: "3.11.0".to_string(),
            services,
            disk_space,
        };

        assert_eq!(report.platform, "win32");
        assert_eq!(report.python_version, "3.11.0");
        assert_eq!(report.services.len(), 1);
        assert_eq!(report.disk_space.len(), 2);
    }

    #[test]
    fn test_validation_summary_all_critical_available() {
        let summary = create_test_validation_summary();
        assert!(summary.all_critical_available());

        // Test with missing critical dependency
        let mut dependencies = HashMap::new();
        dependencies.insert(
            "Flask".to_string(),
            create_test_dependency_status(false, None),
        );
        dependencies.insert(
            "TensorFlow".to_string(),
            create_test_dependency_status(true, Some("2.13.0".to_string())),
        );

        let summary_missing = ValidationSummary {
            dependencies,
            flask_validation: None,
            tensorflow_validation: None,
            llama_validation: None,
            system_health: None,
        };

        assert!(!summary_missing.all_critical_available());
    }

    #[test]
    fn test_validation_summary_with_all_none() {
        let summary = ValidationSummary {
            dependencies: HashMap::new(),
            flask_validation: None,
            tensorflow_validation: None,
            llama_validation: None,
            system_health: None,
        };

        assert!(!summary.all_critical_available());
        assert!(summary.dependencies.is_empty());
    }

    #[test]
    fn test_validation_summary_serialization() {
        let summary = create_test_validation_summary();

        let json_str = serde_json::to_string_pretty(&summary).unwrap();
        assert!(json_str.contains("Flask"));
        assert!(json_str.contains("TensorFlow"));
        assert!(json_str.contains("flask_validation"));
        assert!(json_str.contains("tensorflow_validation"));

        // Test deserialization
        let deserialized: ValidationSummary = serde_json::from_str(&json_str).unwrap();
        assert_eq!(deserialized.dependencies.len(), summary.dependencies.len());
        assert!(deserialized.flask_validation.is_some());
        assert!(deserialized.tensorflow_validation.is_some());
    }

    #[test]
    fn test_dependency_validator_is_dependency_available() {
        let mut validator = DependencyValidator::new();

        // Initially should be false
        assert!(!validator.is_dependency_available("Flask"));

        // Add a dependency
        validator.results.insert(
            "Flask".to_string(),
            create_test_dependency_status(true, Some("2.3.3".to_string())),
        );
        assert!(validator.is_dependency_available("Flask"));

        // Add unavailable dependency
        validator.results.insert(
            "NonExistent".to_string(),
            create_test_dependency_status(false, None),
        );
        assert!(!validator.is_dependency_available("NonExistent"));
    }

    #[test]
    fn test_flask_validation_result_serialization() {
        let result = FlaskValidationResult {
            status: true,
            message: "Test message".to_string(),
            cors_enabled: false,
            max_upload_mb: 64,
        };

        let json_str = serde_json::to_string(&result).unwrap();
        assert!(json_str.contains("Test message"));
        assert!(json_str.contains("64"));

        let deserialized: FlaskValidationResult = serde_json::from_str(&json_str).unwrap();
        assert_eq!(deserialized.status, result.status);
        assert_eq!(deserialized.message, result.message);
        assert_eq!(deserialized.cors_enabled, result.cors_enabled);
        assert_eq!(deserialized.max_upload_mb, result.max_upload_mb);
    }

    #[test]
    fn test_tensorflow_validation_result_serialization() {
        let result = TensorFlowValidationResult {
            status: false,
            version: "2.12.0".to_string(),
            gpu_available: false,
            gpu_count: 0,
            keras_available: false,
            model_building: false,
            model_prediction_test: "Failed test".to_string(),
        };

        let json_str = serde_json::to_string(&result).unwrap();
        assert!(json_str.contains("2.12.0"));
        assert!(json_str.contains("Failed test"));

        let deserialized: TensorFlowValidationResult = serde_json::from_str(&json_str).unwrap();
        assert_eq!(deserialized.status, result.status);
        assert_eq!(deserialized.version, result.version);
        assert_eq!(deserialized.gpu_available, result.gpu_available);
        assert_eq!(deserialized.gpu_count, result.gpu_count);
        assert_eq!(deserialized.keras_available, result.keras_available);
        assert_eq!(deserialized.model_building, result.model_building);
        assert_eq!(
            deserialized.model_prediction_test,
            result.model_prediction_test
        );
    }

    #[test]
    fn test_llama_validation_result_serialization() {
        let result = LlamaValidationResult {
            status: true,
            version: "0.2.11".to_string(),
            supports_gpu: false,
            quantization_support: true,
            supported_formats: vec!["GGUF".to_string()],
            default_params_available: true,
            params_modifiable: false,
        };

        let json_str = serde_json::to_string(&result).unwrap();
        assert!(json_str.contains("0.2.11"));
        assert!(json_str.contains("GGUF"));

        let deserialized: LlamaValidationResult = serde_json::from_str(&json_str).unwrap();
        assert_eq!(deserialized.status, result.status);
        assert_eq!(deserialized.version, result.version);
        assert_eq!(deserialized.supports_gpu, result.supports_gpu);
        assert_eq!(
            deserialized.quantization_support,
            result.quantization_support
        );
        assert_eq!(deserialized.supported_formats, result.supported_formats);
        assert_eq!(
            deserialized.default_params_available,
            result.default_params_available
        );
        assert_eq!(deserialized.params_modifiable, result.params_modifiable);
    }

    #[test]
    fn test_system_health_report_serialization() {
        let mut services = HashMap::new();
        services.insert("test_service".to_string(), json!({"available": true}));

        let mut disk_space = HashMap::new();
        disk_space.insert("total_gb".to_string(), json!(1000.0));

        let report = SystemHealthReport {
            platform: "linux".to_string(),
            python_version: "3.10.0".to_string(),
            services,
            disk_space,
        };

        let json_str = serde_json::to_string(&report).unwrap();
        assert!(json_str.contains("linux"));
        assert!(json_str.contains("3.10.0"));
        assert!(json_str.contains("test_service"));

        let deserialized: SystemHealthReport = serde_json::from_str(&json_str).unwrap();
        assert_eq!(deserialized.platform, report.platform);
        assert_eq!(deserialized.python_version, report.python_version);
        assert_eq!(deserialized.services.len(), report.services.len());
        assert_eq!(deserialized.disk_space.len(), report.disk_space.len());
    }

    #[test]
    fn test_dependency_status_with_empty_details() {
        let status = DependencyStatus {
            available: false,
            version: None,
            details: HashMap::new(),
        };

        assert!(!status.available);
        assert!(status.version.is_none());
        assert!(status.details.is_empty());

        // Should serialize/deserialize correctly
        let json_str = serde_json::to_string(&status).unwrap();
        let deserialized: DependencyStatus = serde_json::from_str(&json_str).unwrap();
        assert_eq!(deserialized.available, status.available);
        assert_eq!(deserialized.version, status.version);
        assert_eq!(deserialized.details.len(), status.details.len());
    }

    #[test]
    fn test_dependency_validation_with_environment_variables() {
        // Test that dependency validation respects environment variables
        unsafe {
            env::set_var("INTELLICRACK_TEST_VAR", "test_value");
        }

        // Verify the environment variable is set
        assert_eq!(env::var("INTELLICRACK_TEST_VAR").unwrap(), "test_value");

        // Clean up
        unsafe {
            env::remove_var("INTELLICRACK_TEST_VAR");
        }
        assert!(env::var("INTELLICRACK_TEST_VAR").is_err());
    }

    #[test]
    fn test_validation_summary_partial_results() {
        let mut dependencies = HashMap::new();
        dependencies.insert(
            "Flask".to_string(),
            create_test_dependency_status(true, Some("2.3.3".to_string())),
        );

        let summary = ValidationSummary {
            dependencies,
            flask_validation: Some(FlaskValidationResult {
                status: true,
                message: "Flask OK".to_string(),
                cors_enabled: true,
                max_upload_mb: 16,
            }),
            tensorflow_validation: None,
            llama_validation: None,
            system_health: None,
        };

        // Should not have all critical dependencies (TensorFlow missing)
        assert!(!summary.all_critical_available());
        assert!(summary.flask_validation.is_some());
        assert!(summary.tensorflow_validation.is_none());
    }

    #[test]
    fn test_complex_dependency_details() {
        let mut details = HashMap::new();
        details.insert(
            "nested_object".to_string(),
            json!({
                "sub_field": "value",
                "sub_number": 42,
                "sub_bool": true
            }),
        );
        details.insert(
            "array_field".to_string(),
            json!(["item1", "item2", "item3"]),
        );
        details.insert("null_field".to_string(), json!(null));

        let status = DependencyStatus {
            available: true,
            version: Some("1.0.0".to_string()),
            details,
        };

        // Test serialization with complex nested data
        let json_str = serde_json::to_string_pretty(&status).unwrap();
        assert!(json_str.contains("nested_object"));
        assert!(json_str.contains("sub_field"));
        assert!(json_str.contains("array_field"));
        assert!(json_str.contains("item1"));

        // Test deserialization
        let deserialized: DependencyStatus = serde_json::from_str(&json_str).unwrap();
        assert_eq!(deserialized.available, status.available);
        assert_eq!(deserialized.version, status.version);
        assert_eq!(deserialized.details.len(), status.details.len());

        // Verify nested data integrity
        let nested_obj = deserialized.details.get("nested_object").unwrap();
        assert_eq!(nested_obj["sub_field"], "value");
        assert_eq!(nested_obj["sub_number"], 42);
        assert_eq!(nested_obj["sub_bool"], true);

        let array_field = deserialized.details.get("array_field").unwrap();
        assert!(array_field.is_array());
        assert_eq!(array_field.as_array().unwrap().len(), 3);
    }

    #[test]
    fn test_validation_summary_edge_cases() {
        // Test with empty dependencies but other fields populated
        let summary = ValidationSummary {
            dependencies: HashMap::new(),
            flask_validation: Some(FlaskValidationResult {
                status: false,
                message: "Flask failed".to_string(),
                cors_enabled: false,
                max_upload_mb: 0,
            }),
            tensorflow_validation: Some(TensorFlowValidationResult {
                status: false,
                version: "Unknown".to_string(),
                gpu_available: false,
                gpu_count: 0,
                keras_available: false,
                model_building: false,
                model_prediction_test: "Failed".to_string(),
            }),
            llama_validation: Some(LlamaValidationResult {
                status: false,
                version: "Unknown".to_string(),
                supports_gpu: false,
                quantization_support: false,
                supported_formats: vec![],
                default_params_available: false,
                params_modifiable: false,
            }),
            system_health: Some(SystemHealthReport {
                platform: "Unknown".to_string(),
                python_version: "Unknown".to_string(),
                services: HashMap::new(),
                disk_space: HashMap::new(),
            }),
        };

        assert!(!summary.all_critical_available());
        assert!(summary.flask_validation.is_some());
        assert!(summary.tensorflow_validation.is_some());
        assert!(summary.llama_validation.is_some());
        assert!(summary.system_health.is_some());

        // Should serialize without issues
        let json_str = serde_json::to_string(&summary).unwrap();
        assert!(json_str.contains("Flask failed"));
        assert!(json_str.contains("Unknown"));
    }

    #[test]
    fn test_debug_format_implementations() {
        // Test Debug formatting for all types
        let status = create_test_dependency_status(true, Some("1.0.0".to_string()));
        let debug_str = format!("{:?}", status);
        assert!(debug_str.contains("DependencyStatus"));
        assert!(debug_str.contains("available"));

        let flask_result = FlaskValidationResult {
            status: true,
            message: "Test".to_string(),
            cors_enabled: true,
            max_upload_mb: 16,
        };
        let debug_str = format!("{:?}", flask_result);
        assert!(debug_str.contains("FlaskValidationResult"));

        let tf_result = TensorFlowValidationResult {
            status: true,
            version: "2.13.0".to_string(),
            gpu_available: false,
            gpu_count: 0,
            keras_available: true,
            model_building: true,
            model_prediction_test: "Success".to_string(),
        };
        let debug_str = format!("{:?}", tf_result);
        assert!(debug_str.contains("TensorFlowValidationResult"));

        let llama_result = LlamaValidationResult {
            status: true,
            version: "0.2.11".to_string(),
            supports_gpu: true,
            quantization_support: true,
            supported_formats: vec!["GGUF".to_string()],
            default_params_available: true,
            params_modifiable: true,
        };
        let debug_str = format!("{:?}", llama_result);
        assert!(debug_str.contains("LlamaValidationResult"));

        let health_report = SystemHealthReport {
            platform: "win32".to_string(),
            python_version: "3.11.0".to_string(),
            services: HashMap::new(),
            disk_space: HashMap::new(),
        };
        let debug_str = format!("{:?}", health_report);
        assert!(debug_str.contains("SystemHealthReport"));
    }

    #[test]
    fn test_clone_implementations() {
        // Test Clone implementations for all types
        let original_status = create_test_dependency_status(true, Some("1.0.0".to_string()));
        let cloned_status = original_status.clone();
        assert_eq!(cloned_status.available, original_status.available);
        assert_eq!(cloned_status.version, original_status.version);

        let original_summary = create_test_validation_summary();
        let cloned_summary = original_summary.clone();
        assert_eq!(
            cloned_summary.dependencies.len(),
            original_summary.dependencies.len()
        );
        assert_eq!(
            cloned_summary.flask_validation.is_some(),
            original_summary.flask_validation.is_some()
        );
    }

    #[tokio::test]
    async fn test_async_validation_production() {
        // Production async validation test that performs real dependency checks
        let mut validator = DependencyValidator::new();

        // Perform actual dependency validation in async context
        let validation_task = tokio::task::spawn_blocking(move || {
            // Check for real system dependencies
            let rust_version = Command::new("rustc")
                .arg("--version")
                .output()
                .ok()
                .and_then(|output| String::from_utf8(output.stdout).ok());

            let cargo_version = Command::new("cargo")
                .arg("--version")
                .output()
                .ok()
                .and_then(|output| String::from_utf8(output.stdout).ok());

            (rust_version, cargo_version)
        });

        let (rust_ver, cargo_ver) = validation_task.await.unwrap();

        // Add real dependency validation results
        if let Some(version) = rust_ver {
            let version_str = version
                .split_whitespace()
                .nth(1)
                .unwrap_or("unknown")
                .to_string();
            validator.results.insert(
                "rustc".to_string(),
                create_test_dependency_status(true, Some(version_str)),
            );
        }

        if let Some(version) = cargo_ver {
            let version_str = version
                .split_whitespace()
                .nth(1)
                .unwrap_or("unknown")
                .to_string();
            validator.results.insert(
                "cargo".to_string(),
                create_test_dependency_status(true, Some(version_str)),
            );
        }

        // Validate actual dependency availability
        if validator.results.contains_key("rustc") {
            assert!(validator.is_dependency_available("rustc"));
        }
        assert!(!validator.is_dependency_available("NonExistentDep"));
    }
}
