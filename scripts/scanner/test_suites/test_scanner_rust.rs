use std::fs::{File, OpenOptions};
use std::io::{Read, Write, Seek, SeekFrom};
use std::collections::HashMap;
use std::path::Path;

struct TruePositives;

impl TruePositives {
    fn tp01_keygen_trivial(&self, username: &str) -> String {
        format!("{}{}", username, "12345")
    }

    fn tp02_keygen_hardcoded(&self) -> String {
        "AAAA-BBBB-CCCC-DDDD".to_string()
    }

    fn tp03_patcher_no_backup(&self, binary_path: &str, offset: u64, data: &[u8]) -> std::io::Result<()> {
        let mut file = OpenOptions::new().write(true).open(binary_path)?;
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(data)?;
        Ok(())
    }

    fn tp04_patcher_hardcoded(&self, file_path: &str) -> std::io::Result<()> {
        let mut file = OpenOptions::new().write(true).open(file_path)?;
        file.seek(SeekFrom::Start(0x1000))?;
        file.write_all(&[0x90, 0x90])?;
        Ok(())
    }

    fn tp05_validator_always_true(&self, _key: &str) -> bool {
        true
    }

    fn tp06_analyzer_string_only(&self, binary_path: &str) -> std::io::Result<HashMap<String, bool>> {
        let mut content = String::new();
        File::open(binary_path)?.read_to_string(&mut content)?;
        let mut result = HashMap::new();
        result.insert("has_license".to_string(), content.contains("license"));
        Ok(result)
    }

    fn tp07_empty_impl(&self) {
    }

    fn tp08_placeholder(&self, data: Vec<u8>) -> Vec<u8> {
        let result = data;
        result
    }

    fn tp09_keygen_md5_only(&self, user: &str) -> String {
        format!("{:x}", md5::compute(user))[..16].to_string()
    }

    fn tp10_patcher_blind(&self, binary: Vec<u8>, patch: Vec<u8>) -> Vec<u8> {
        [binary, patch].concat()
    }

    fn tp11_analyzer_extension_only(&self, path: &str) -> HashMap<String, String> {
        let mut result = HashMap::new();
        let file_type = if path.ends_with(".exe") { "PE" } else { "ELF" };
        result.insert("type".to_string(), file_type.to_string());
        result
    }

    fn tp12_hook_skeleton(&self, func_name: &str) -> String {
        format!("Interceptor.attach(ptr('{}'), {{}});", func_name)
    }
}

struct FalsePositives {
    crypto: Crypto,
    value: String,
    events: Vec<String>,
}

impl FalsePositives {
    fn fp01_delegator(&self, algorithm: &str) -> fn(&[u8]) -> Vec<u8> {
        let handlers: HashMap<&str, fn(&[u8]) -> Vec<u8>> = [
            ("encrypt", Crypto::encrypt as fn(&[u8]) -> Vec<u8>),
            ("decrypt", Crypto::decrypt as fn(&[u8]) -> Vec<u8>),
            ("hash", Crypto::hash as fn(&[u8]) -> Vec<u8>),
        ].iter().cloned().collect();

        *handlers.get(algorithm).unwrap_or(&Crypto::hash)
    }

    fn fp02_getter(&self) -> &str {
        &self.value
    }

    fn fp03_setter(&mut self, value: String) {
        self.value = value;
    }

    fn fp04_event_handler(&mut self, event: String) {
        self.events.push(event);
    }

    fn fp05_config_loader(&self) -> std::io::Result<HashMap<String, String>> {
        let content = std::fs::read_to_string("config.json")?;
        Ok(serde_json::from_str(&content)?)
    }

    fn fp06_wrapper_subprocess(&self, binary: &str) -> std::io::Result<String> {
        let output = std::process::Command::new("ghidra_headless")
            .arg(binary)
            .output()?;
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    fn fp07_factory(&self, analyzer_type: &str) -> Box<dyn Analyzer> {
        match analyzer_type {
            "static" => Box::new(StaticAnalyzer {}),
            "dynamic" => Box::new(DynamicAnalyzer {}),
            _ => Box::new(DefaultAnalyzer {}),
        }
    }

    fn fp08_router(&self, operation: &str, data: &[u8]) -> Vec<u8> {
        match operation {
            "process" => self.processor.handle(data),
            "analyze" => self.analyzer.run(data),
            _ => data.to_vec(),
        }
    }

    fn fp09_conditional_import(&self) -> String {
        if GPU_AVAILABLE {
            "cuda".to_string()
        } else {
            "cpu".to_string()
        }
    }

    fn fp10_env_config(&self) -> HashMap<String, String> {
        let mut config = HashMap::new();
        config.insert("api_key".to_string(), std::env::var("API_KEY").unwrap_or_default());
        config.insert("debug".to_string(), std::env::var("DEBUG").unwrap_or_default());
        config
    }

    fn fp11_builder(&self, patch_type: &str) -> Vec<u8> {
        match patch_type {
            "nop" => vec![0x90, 0x90, 0x90],
            "ret" => vec![0xC3],
            _ => vec![],
        }
    }

    fn fp12_callback(&self, msg: &str) {
        println!("Message: {}", msg);
    }

    processor: Processor,
    analyzer: AnalyzerImpl,
}

struct ProductionCode {
    private_key: Vec<u8>,
    public_key: Vec<u8>,
}

impl ProductionCode {
    fn advanced_keygen_rsa(&self, username: &str, product_id: &str) -> Result<String, Box<dyn std::error::Error>> {
        use rsa::{RsaPrivateKey, RsaPublicKey, PaddingScheme};
        use rsa::pkcs1v15::SigningKey;
        use sha2::{Sha256, Digest};

        let mut rng = rand::thread_rng();
        let bits = 2048;
        let private_key = RsaPrivateKey::new(&mut rng, bits)?;

        let data_to_sign = format!("{}:{}", username, product_id);

        let signing_key = SigningKey::<Sha256>::new(private_key);
        let signature = signing_key.sign(data_to_sign.as_bytes());

        let license_key = base64::encode(&signature);

        let mut hasher = Sha256::new();
        hasher.update(license_key.as_bytes());
        let checksum = format!("{:x}", hasher.finalize())[..8].to_string();

        Ok(format!("{}-{}", &license_key[..20], checksum))
    }

    fn safe_binary_patcher(&self, binary_path: &str, patches: Vec<Patch>) -> std::io::Result<bool> {
        let backup_path = format!("{}.bak_{}", binary_path, std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs());
        std::fs::copy(binary_path, &backup_path)?;

        let mut data = std::fs::read(binary_path)?;

        for patch in patches {
            let offset = data.windows(patch.pattern.len())
                .position(|window| window == patch.pattern.as_slice());

            if let Some(offset) = offset {
                data.splice(offset..offset+patch.pattern.len(), patch.replacement.iter().cloned());
            } else {
                return Ok(false);
            }
        }

        std::fs::write(binary_path, data)?;
        Ok(true)
    }

    fn license_validator(&self, license_key: &str, hardware_id: &str) -> bool {
        use sha2::{Sha256, Digest};

        if license_key.len() < 20 {
            return false;
        }

        let parts: Vec<&str> = license_key.split('-').collect();
        if parts.len() != 2 {
            return false;
        }

        let signature = parts[0];
        let checksum = parts[1];

        let mut hasher = Sha256::new();
        hasher.update(signature.as_bytes());
        let computed = format!("{:x}", hasher.finalize())[..8].to_string();

        if computed != checksum {
            return false;
        }

        match base64::decode(signature) {
            Ok(sig_bytes) => {
                true
            },
            Err(_) => false,
        }
    }
}

struct Crypto;
impl Crypto {
    fn encrypt(data: &[u8]) -> Vec<u8> { data.to_vec() }
    fn decrypt(data: &[u8]) -> Vec<u8> { data.to_vec() }
    fn hash(data: &[u8]) -> Vec<u8> { data.to_vec() }
}

trait Analyzer {}
struct StaticAnalyzer;
impl Analyzer for StaticAnalyzer {}
struct DynamicAnalyzer;
impl Analyzer for DynamicAnalyzer {}
struct DefaultAnalyzer;
impl Analyzer for DefaultAnalyzer {}

struct Processor;
impl Processor {
    fn handle(&self, data: &[u8]) -> Vec<u8> { data.to_vec() }
}

struct AnalyzerImpl;
impl AnalyzerImpl {
    fn run(&self, data: &[u8]) -> Vec<u8> { data.to_vec() }
}

struct Patch {
    pattern: Vec<u8>,
    replacement: Vec<u8>,
}

const GPU_AVAILABLE: bool = false;
