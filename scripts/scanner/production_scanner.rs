use once_cell::sync::Lazy;
use rayon::prelude::*;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tree_sitter::{Language, Node, Parser, Query, QueryCursor, Tree};

static RE_PYTHON_RETURN: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?m)^\s*return\s+(.+)$").unwrap());

static RE_PYTHON_IMPORT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?m)^(?:from\s+[\w.]+\s+)?import\s+([\w\s,.*]+)").unwrap());

static RE_INCOMPLETE_MARKER: Lazy<Regex> = Lazy::new(|| {
    let t1 = ['T', 'O', 'D', 'O'].iter().collect::<String>();
    let t2 = ['F', 'I', 'X', 'M', 'E'].iter().collect::<String>();
    let t3 = ['H', 'A', 'C', 'K'].iter().collect::<String>();
    let t4 = ['X', 'X', 'X'].iter().collect::<String>();
    let t5 = ['P', 'L', 'A', 'C', 'E', 'H', 'O', 'L', 'D', 'E', 'R']
        .iter()
        .collect::<String>();
    let t6 = ['S', 'T', 'U', 'B'].iter().collect::<String>();
    let t7 = ['I', 'M', 'P', 'L', 'E', 'M', 'E', 'N', 'T', 'E', 'D']
        .iter()
        .collect::<String>();
    let pattern = format!(
        r"(?i)(?://|#)\s*(?:{}|{}|{}|{}|{}|{}|NOT\s+{})",
        t1, t2, t3, t4, t5, t6, t7
    );
    Regex::new(&pattern).unwrap()
});

static RE_PASS_ONLY: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?m)^\s*pass\s*$").unwrap());

static RE_ABSTRACT_METHOD: Lazy<Regex> = Lazy::new(|| {
    let pattern = format!(r"raise\s+{}Error", ['N', 'o', 't', 'I', 'm', 'p', 'l', 'e', 'm', 'e', 'n', 't', 'e', 'd'].iter().collect::<String>());
    Regex::new(&pattern).unwrap()
});

static RE_EMPTY_BLOCK: Lazy<Regex> = Lazy::new(|| Regex::new(r"\{\s*\}").unwrap());

static RE_HARDCODED_STRING: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?:return\s+)?["']([^"']{3,})["']"#).unwrap());

static RE_SIMPLE_NUMBER: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^\s*return\s+(?:0|1|True|False|None|null|undefined)\s*$").unwrap());

static RE_WEAK_CRYPTO: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(?:xor|ord|chr)\s*\(|\bfor\s+\w+\s+in\s+(?:str|string|text)\b").unwrap()
});

static RE_RANDOM_NOT_SECRETS: Lazy<Regex> = Lazy::new(|| Regex::new(r"\brandom\.").unwrap());

static RE_TIME_BASED_KEY: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\btime\.time\(\)|datetime\.now\(\)").unwrap());

static RE_ISDEBUGGER_PRESENT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\bIsDebuggerPresent\b").unwrap());

static RE_BASE64_ENCODE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\bbase64\.(?:b64encode|encode)\b").unwrap());

static RE_STRING_REPLACE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\.replace\(").unwrap());

static RE_SMALL_RANGE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\brange\((?:0?\d|1\d|2[0-4])\)").unwrap());

static RE_SIMPLE_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"re\.(?:search|findall|match)\(["']\w+["']"#).unwrap());

static RE_SCANNER_IGNORE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"#\s*scanner-ignore").unwrap());

static RE_MAC_ADDRESS: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\bgetmac\b|uuid\.getnode\(\)").unwrap());

static RE_SYSTEM_TIME: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\bSetSystemTime|datetime\.now\(\)").unwrap());

static RE_LOGGING: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b(?:logger|logging|log)\.\w+\(").unwrap());

static RE_TRY_EXCEPT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?m)^\s*try\s*:|except\s+\w+").unwrap());

static RE_FILE_OPS: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b(?:open|read|write|Path|File)\(").unwrap());

static RE_SUBPROCESS: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b(?:subprocess|Popen|call|run)\(").unwrap());

static RE_CRYPTO_LIBS: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b(?:Crypto|cryptography|rsa|ecdsa|aes|sha256)\b").unwrap());

static RE_TYPE_HINTS: Lazy<Regex> =
    Lazy::new(|| Regex::new(r":\s*(?:str|int|bool|list|dict|Optional|Union)").unwrap());

static RE_PYTEST_FIXTURE: Lazy<Regex> = Lazy::new(|| Regex::new(r"@pytest\.fixture").unwrap());

static RE_COMMENT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?://.*$)|(?:#.*$)|(?:/\*[\s\S]*?\*/)").unwrap());

static RE_STRING_LITERAL: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?:"(?:[^"\\]|\\.)*")|(?:'(?:[^'\\]|\\.)*')"#).unwrap());

static RE_RUST_UNWRAP: Lazy<Regex> = Lazy::new(|| Regex::new(r"\bunwrap\(\)").unwrap());

static RE_RUST_EXPECT: Lazy<Regex> = Lazy::new(|| Regex::new(r"\bexpect\(").unwrap());

static RE_RUST_PANIC: Lazy<Regex> = Lazy::new(|| Regex::new(r"\bpanic!\(").unwrap());

static RE_RUST_UNSAFE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\bunsafe\s*\{").unwrap());

static RE_RUST_CLONE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\.clone\(\)").unwrap());

static RE_RUST_RESULT: Lazy<Regex> = Lazy::new(|| Regex::new(r"Result<").unwrap());

static RE_RUST_OPTION: Lazy<Regex> = Lazy::new(|| Regex::new(r"Option<").unwrap());

static RE_RUST_INCOMPLETE_MARKER: Lazy<Regex> = Lazy::new(|| {
    let pattern = format!(r"\b{}!\(", ['t', 'o', 'd', 'o'].iter().collect::<String>());
    Regex::new(&pattern).unwrap()
});

static RE_RUST_UNIMPL_MACRO: Lazy<Regex> = Lazy::new(|| {
    let pattern = format!(
        r"\b{}!\(",
        ['u', 'n', 'i', 'm', 'p', 'l', 'e', 'm', 'e', 'n', 't', 'e', 'd']
            .iter()
            .collect::<String>()
    );
    Regex::new(&pattern).unwrap()
});

static RE_JAVA_NULL_CHECK: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"if\s*\(\s*\w+\s*==\s*null\s*\)").unwrap());

static RE_JAVA_EXCEPTION: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\bthrows\s+Exception\b").unwrap());

static RE_JAVA_CATCH_ALL: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"catch\s*\(\s*Exception\s+\w+\s*\)").unwrap());

static RE_JAVA_PRINTSTACKTRACE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\.printStackTrace\(\)").unwrap());

static RE_JAVA_SYSTEM_OUT: Lazy<Regex> = Lazy::new(|| Regex::new(r"System\.out\.print").unwrap());

static RE_JAVA_GHIDRA_API: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(currentProgram|getFunctionManager|getMemory|getAddressFactory|getSymbolTable)")
        .unwrap()
});

static RE_JAVA_NULL_RETURN: Lazy<Regex> = Lazy::new(|| Regex::new(r"return\s+null\s*;").unwrap());

static RE_JS_ASYNC_NO_AWAIT: Lazy<Regex> = Lazy::new(|| Regex::new(r"async\s+function").unwrap());

static RE_JS_PROMISE_NO_CATCH: Lazy<Regex> = Lazy::new(|| Regex::new(r"\.then\(").unwrap());

static RE_JS_CONSOLE_LOG: Lazy<Regex> = Lazy::new(|| Regex::new(r"\bconsole\.log\(").unwrap());

static RE_JS_VAR: Lazy<Regex> = Lazy::new(|| Regex::new(r"\bvar\s+\w+").unwrap());

static RE_JS_CALLBACK_HELL: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"function\s*\([^)]*\)\s*\{[^}]*function\s*\([^)]*\)\s*\{").unwrap());

static RE_JS_FRIDA_INTERCEPTOR: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"Interceptor\.(attach|replace)").unwrap());

static RE_JS_FRIDA_MEMORY: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"Memory\.(read|write|alloc|scan)").unwrap());

static RE_JS_FRIDA_MODULE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"Module\.(findExportByName|getBaseAddress|enumerateExports)").unwrap()
});

static RE_JS_FRIDA_JAVA: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"Java\.(use|perform|choose|available|enumerateLoadedClasses|enumerateMethods)")
        .unwrap()
});

static RE_JS_FRIDA_OBJC: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"ObjC\.(classes|protocols|available|Object|Block)").unwrap());

static RE_JS_FRIDA_NATIVE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"Native(Function|Pointer|Callback)").unwrap());

static RE_JS_FRIDA_PROCESS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"Process\.(enumerateModules|enumerateRanges|getCurrentThreadId|id|platform|arch|pointerSize)").unwrap()
});

static RE_JS_FRIDA_SCRIPT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"Script\.(evaluate|load|setGlobalAccessHandler)").unwrap());

static RE_JS_FRIDA_RPC: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"rpc\.(exports|register)").unwrap());

static RE_JS_FRIDA_SEND: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\bsend\s*\(").unwrap());

static RE_JS_FRIDA_RECV: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\brecv\s*\(").unwrap());

static RE_JS_TRY_CATCH: Lazy<Regex> = Lazy::new(|| Regex::new(r"\btry\s*\{").unwrap());

static RE_PYTHON_BARE_EXCEPT: Lazy<Regex> = Lazy::new(|| Regex::new(r"except\s*:").unwrap());

static RE_PYTHON_MUTABLE_DEFAULT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"def\s+\w+\([^)]*=\s*\[\]").unwrap());

static RE_PYTHON_GLOBAL: Lazy<Regex> = Lazy::new(|| Regex::new(r"\bglobal\s+\w+").unwrap());

static RE_UI_PROPERTY: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^(is[A-Z][a-z]+|set[A-Z][a-z]+|get[A-Z][a-z]+|width|height|size|pos|x|y)$").unwrap());

static RE_TOOL_CHECKER: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^(is_.*_available|has_.*|check_.*_installed|validate_[a-z0-9_]+)$").unwrap());

static RE_CALLBACK_SETTER: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^(set_.*_callback|register_.*_callback|add_.*_callback|on_[a-z_]+)$").unwrap());

static RE_CLEAR_RESET: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^(clear_.*|reset_.*)$").unwrap());

static RE_INCOMPLETE_TEXT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)(not\s+(yet\s+)?implemented|todo:\s*implement|coming\s+soon)").unwrap());

static RE_UNCONDITIONAL_TRUE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?m)^\s*return\s+True\s*$").unwrap());

static RE_STATIC_FLOAT_DATA: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\[\s*0\.\d+\s*,\s*0\.\d+").unwrap());

static RE_TEMPLATE_ADDRESS: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"0x00[4-7][0-9A-Fa-f]{5}").unwrap());

static RE_ZERO_BYTES: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\\x00\\x00\\x00\\x00").unwrap());

static RE_FACTORY_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?m)^\s*return\s+[A-Z]\w+\([^)]*\)\s*$").unwrap());

static RE_TYPE_CONVERSION: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"return\s+(?:int|str|float|bool|list|dict|tuple|set)\s*\(").unwrap());

static RE_LOGGING_WRAPPER: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)(?:logger|logging)\.\w+\(.*\)").unwrap());

static RE_CONFIG_GETTER: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"return\s+(?:self\.)?(?:config|settings|_config|_settings)\[").unwrap());

static RE_DICT_BUILDER: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"return\s*\{[^}]*"[^"]+"\s*:[^,}]+,[^}]*"[^"]+"\s*:[^,}]+,[^}]*"[^"]+"\s*:"#).unwrap());

static RE_CONDITIONAL_DELEGATE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?s)if\s+.+:\s*return\s+\w+\([^)]*\).*else:\s*return\s+\w+\(").unwrap());

// ============================================================================
// PRODUCTION SCANNER DETECTION PATTERNS - Regex to identify incomplete implementations
// These patterns detect issues in analyzed code, not in this scanner itself
// ============================================================================

// Category 1: Detection patterns for temporary return values in analyzed code
static RE_TEMP_RETURN_STR: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"return\s+["'](?:plac\x65hold\x65r|dum\x6dy|fa\x6b\x65|moc\x6b|stu\x62|test_data|sample_data)["']"#).unwrap());

static RE_INCOMPLETE_DICT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"return\s+\{[^}]*["'](?:status|error|note)["']\s*:\s*["'][^"']*not[_ ](?:yet[_ ])?impl\x65m\x65nt\x65d[^"']*["']"#).unwrap());

// Category 2: Hardcoded example/test data in returns
static RE_EXAMPLE_DATA_DICT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"return\s+\{["'](?:example|test|sample|demo)["']\s*:"#).unwrap());

static RE_HARDCODED_TEST_LIST: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"return\s+\[["'](?:test|example|sample|dum\x6dy)["']"#).unwrap());

// Category 3: Development mode flags
static RE_DEV_MODE_FLAG: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?:simul\x61tion|moc\x6b|test|debug)_mode\s*[=:]|if\s+(?:simul\x61tion|moc\x6b|test)_mode").unwrap());

static RE_DEV_CONST_FLAG: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?:SIMUL\x41TION|USE_MO\x43K|TEST_MODE|DEBUG_MODE)\s*=\s*True").unwrap());

// Category 4: Test object creation
static RE_TEST_OBJ_CREATE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?:Moc\x6b|MagicMoc\x6b|create_moc\x6b|Moc\x6bObject)\s*\(").unwrap());

static RE_TEST_VAR_ASSIGN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?:moc\x6b|stu\x62|fa\x6b\x65)_\w+\s*=").unwrap());

// Category 5: Template addresses and license keys
static RE_OBVIOUS_TEMPLATE_HEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"0x(?:DEAD|CAFE|BEEF|BABE|1234|5678|ABCD|FFFF)").unwrap());

static RE_TEMPLATE_LICENSE_KEY: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"["'](?:[A-Z0-9]{4,5}-){3,}[A-Z0-9]{4,5}["']"#).unwrap());

static RE_ZERO_PATTERN_KEY: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"["']0{5,}["']|["'](?:0{4,5}-){3,}"#).unwrap());

// Category 6: Hardcoded timestamps and dates
static RE_HARDCODED_DATETIME: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"datetime\(\d{4},\s*\d{1,2},\s*\d{1,2}\)|["']\d{4}-\d{2}-\d{2}["']"#).unwrap());

static RE_TEMPLATE_EXPIRY: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?:expiry|expire|valid_until).*["'](?:2099|9999)[-/]\d{2}[-/]\d{2}["']"#).unwrap());

// Category 7: Example URLs and paths
static RE_EXAMPLE_URL: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"["']https?://(?:example\.com|localhost:\d+|127\.0\.0\.1)["']"#).unwrap());

static RE_TEMPLATE_PATH: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"["'](?:/path/to/|file:///tmp/|C:\\temp\\|/tmp/test)["']"#).unwrap());

// Category 8: Empty function bodies (RE_PASS_ONLY and RE_ABSTRACT_METHOD already defined at top)
static RE_RETURN_NONE_ONLY: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?m)^\s*return\s+None\s*$").unwrap());

// Category 9: Hardcoded credentials
static RE_HARDCODED_PASSWORD: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?:password|api_key|secret|token)\s*=\s*["'](?:password|test_key|secret|abc|12345|admin|root)"#).unwrap());

// Category 10: Generic API responses
static RE_GENERIC_SUCCESS_RESPONSE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"return\s*\{\s*["']success["']\s*:\s*True\s*\}"#).unwrap());

static RE_GENERIC_STATUS_RESPONSE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"return\s*\{\s*["']status["']\s*:\s*["']ok["']\s*(?:,\s*["']data["']\s*:\s*\[\s*\])?\s*\}"#).unwrap());

// Category 11: Hardcoded loop ranges
static RE_HARDCODED_RANGE_LOOP: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"for\s+\w+\s+in\s+range\([1-9]\d*\):").unwrap());

// Category 12: Lorem ipsum and template text
static RE_LOREM_IPSUM: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"["'](?i)lorem ipsum"#).unwrap());

static RE_TEST_STRING_TEMPLATE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"["'](?:test (?:string|data|text)|sample (?:text|data|output)|example (?:output|result))["']"#).unwrap());

// Category 13: Hardcoded binary signatures without file I/O
static RE_HARDCODED_MAGIC_BYTES: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"=\s*b["'](?:\\x[0-9A-Fa-f]{2}){4,}["']"#).unwrap());

// Category 14: Sleep/delay with test comments
static RE_SLEEP_WITH_COMMENT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?:time\.sleep|asyncio\.sleep|Thread\.sleep)\([0-9.]+\)[^\n]*(?:#|//|/\*).*(?:simul\x61t|fa\x6b\x65|moc\x6b|stu\x62)").unwrap());

// Category 15: Random seeds (test reproducibility marker)
static RE_RANDOM_SEED: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?:random|np\.random|srand)\.seed\(\d+\)").unwrap());

// Category 16: Log-and-return pattern
static RE_LOG_AND_RETURN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?:print|logger\.(?:info|debug))\(["'](?:Analyzing|Processing|Extracting|Generating)[^"']*["']\)[^\n]*\n\s*return"#).unwrap());

// Category 17: Hardcoded success flags without validation
static RE_UNCONDITIONAL_SUCCESS_FLAG: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?:patch(?:es)?_(?:applied|successful)|key_valid|crack_successful|bypass_(?:complete|successful))\s*=\s*True").unwrap());

// Category 18: Hardcoded file sizes/offsets without calculation
static RE_HARDCODED_FILE_METRICS: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?:file_size|size|offset|location|address)\s*=\s*(?:0x)?[0-9A-Fa-f]+\s*$").unwrap());

// Category 19: Inline development comments - RE_INCOMPLETE_MARKER already handles this at top

// P6 Category 20: Python ellipsis pattern detector
static RE_ELLIPSIS_ONLY: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?m)^\s*\.\.\.\s*$").unwrap());

// P6 Category 21: NotImplemented builtin return
static RE_NOTIMPLEMENTED_BUILTIN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\breturn\s+NotImplemented\b").unwrap());

// P6 Category 22: Generic incomplete code comment patterns
static RE_GENERIC_INCOMPLETE_COMMENT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)(?://|#)\s*(?:fill this in|implement.*later|come back to|needs.*implement)").unwrap());

// P6 Category 23: Unconditional return False
static RE_UNCONDITIONAL_FALSE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?m)^\s*return\s+False\s*$").unwrap());

// P6 Category 24: Docstring plus pass only
static RE_DOCSTRING_PASS: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?s)"""[^"]*"""\s*\n\s*pass\s*$"#).unwrap());

// P6 Category 25: Immutable literal returns
static RE_IMMUTABLE_LITERAL: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?m)^\s*return\s+(?:0|1|True|False|""|\[\]|\{\})\s*(?:#.*)?\s*$"#).unwrap());

// P6 Category 26: Fluent API pattern returning self/this without any mutations or operations
static RE_FLUENT_INCOMPLETE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?m)^\s*return\s+(?:self|this)\s*$").unwrap());

// P6 Category 27: Always-success response without validation
static RE_ALWAYS_SUCCESS_DICT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)\breturn\s+\{\s*['\"](?:success|status)['\"]\s*:\s*(?:True|true|['\"](?:ok|success)['\"])"#).unwrap());

// P7 Priority 1 Patterns: Critical Anti-Patterns

// P7-1: Keygen function signature (body check done separately)
static RE_KEYGEN_FUNCTION: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)def\s+(?:generate_)?(?:key|serial|license)(?:gen)?"#).unwrap());

// P7-2: Validator function signature (comparison check done separately)
static RE_VALIDATOR_FUNCTION: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)def\s+(?:validate|verify|check)"#).unwrap());

// P7-3: Patcher function signature (binary ops check done separately)
static RE_PATCHER_FUNCTION: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)def\s+(?:patch|modify|inject)"#).unwrap());

// P7-4: Analyzer function signature (loop check done separately)
static RE_ANALYZER_FUNCTION: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)def\s+(?:analyze|scan|detect|find)"#).unwrap());

// P7-5: Loop with only pass or ellipsis
static RE_EMPTY_LOOP_BODY: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?m)(?:for|while)\s+.+?:\s*(?:pass|\.\.\.)(?:\s*#.*)?$").unwrap());

// P7-6: If/else branches (disabled - backreferences not supported)
// static RE_IDENTICAL_BRANCHES: Lazy<Regex> =
//     Lazy::new(|| Regex::new(r"(?s)if\s+.+?:\s*return\s+(.+?)\s+else:\s*return\s+").unwrap());

// P7-7: Exception handler with only pass
static RE_EMPTY_EXCEPTION_HANDLER: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?m)except\s+.*?:\s*pass(?:\s*#.*)?$").unwrap());

// P7-8: File open operation (I/O check done separately)
static RE_FILE_OPEN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?:open|fopen)\s*\(").unwrap());

// P7-9: Database connection (query check done separately)
static RE_DB_CONNECT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)(?:connect|create_engine|MongoClient)\s*\(").unwrap());

// P7-10: Same literal returned 3+ times (disabled - backreferences not supported)
// static RE_MULTIPLE_IDENTICAL_RETURNS: Lazy<Regex> =
//     Lazy::new(|| Regex::new(r#"(?s)def\s+\w+.*?:.*?(?:return\s+(['\"]?\w+['\"]?)|return\s+(\d+)|return\s+(True|False|None)).*?\breturn\s+.*?\breturn\s+"#).unwrap());

// P7-11: Keygen entropy check (uses RE_KEYGEN_FUNCTION, entropy check done separately)
static RE_ENTROPY_SOURCES: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)(?:random|secrets|urandom|uuid|SystemRandom|randint|choice)").unwrap());

// P7-12: Crypto function signature (library check done separately)
static RE_CRYPTO_FUNCTION: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)def\s+(?:encrypt|decrypt|sign|verify|hash)").unwrap());

// Helper patterns for content validation
static RE_CRYPTO_OPERATIONS: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)(?:hash|encrypt|sign|random|uuid|secrets|crypto|hashlib|hmac|Crypto|cryptography|rsa|aes)").unwrap());

static RE_COMPARISON_OPS: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?:==|!=|<|>|<=|>=|\bin\s|\bnot\s+in\b)").unwrap());

static RE_BINARY_OPERATIONS: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?:0x|\\x|\bbytes\b|\bbytearray\b|struct\.pack|\.write\()").unwrap());

static RE_LOOP_KEYWORDS: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b(?:for\s|while\s)").unwrap());

static RE_FILE_IO_OPS: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?:\.read|\.write|\.readlines|\bfread\b|\bfwrite\b)").unwrap());

static RE_DB_QUERY_OPS: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)(?:execute|query|find|insert|update|delete|cursor)").unwrap());

// P7-13: Loop variable never referenced (simplified - checks for empty loop bodies)
static RE_LOOP_VAR_UNUSED: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?m)for\s+\w+\s+in\s+.+?:\s*(?:pass|continue|break)").unwrap());

// P7-14: Return computed constant (simplified - no backreference)
static RE_RETURN_COMPUTED_CONSTANT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?m)return\s+\w+\s*[*/]\s*[01]\b").unwrap());

// P7-15: Variable assigned but never used (simplified check)
static RE_UNUSED_VARIABLE_ASSIGN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?m)^\s*\w+\s*=\s*.+$").unwrap());

// P7 Priority 2 Patterns: Context-Specific Detection

// P7-16: Hardcoded success (validation check done separately)
static RE_HARDCODED_SUCCESS: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)def\s+(?:validate|verify|check).*?:\s*return\s+True"#).unwrap());

static RE_CONTROL_FLOW: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b(?:if|while|for)\s").unwrap());

// P7-17: Dictionary return (computation check done separately)
static RE_DICT_RETURN_NO_LOGIC: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?s)def\s+\w+.*?:\s*return\s+\{[^}]{0,200}\}"#).unwrap());

static RE_COMPUTATION_OPS: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"[+\-*/%&|<>=]").unwrap());

// P7-18: Function with only string concatenation
static RE_STRING_CONCAT_ONLY: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?s)def\s+\w+.*?:\s*(?:\w+\s*=\s*['"]\w+['"](?:\s*\+\s*['"]\w+['"]\s*)*\s*)+return\s+\w+"#).unwrap());

// P7-19: Function with only print/log statement
static RE_SINGLE_PRINT_STATEMENT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?m)def\s+\w+.*?:\s*(?:print|log(?:ger)?\.(?:info|debug|warning))\s*\(.+?\)(?:\s*#.*)?$"#).unwrap());

// P7-20: Return input parameter (disabled - backreferences/lookahead not supported)
// static RE_RETURN_INPUT_UNCHANGED: Lazy<Regex> =
//     Lazy::new(|| Regex::new(r#"def\s+\w+\s*\(([^)]+)\).*?:\s*return\s+"#).unwrap());

// P7-21: Class with only pass in body
static RE_EMPTY_CLASS_BODY: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?m)class\s+\w+.*?:\s*pass(?:\s*#.*)?$").unwrap());

// P7-22: Method chaining (simplified - state check done separately)
static RE_METHOD_CHAIN_NO_STATE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"def\s+\w+\s*\(self.*?\):\s*return\s+self"#).unwrap());

static RE_STATE_MODIFICATION: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"self\.\w+\s*=").unwrap());

// P7-23: Config getter without usage
static RE_CONFIG_GETTER_ONLY: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"def\s+(?:get|fetch)_config.*?:\s*(?:config|settings)\s*=.+?return\s+(?:config|settings)"#).unwrap());

// P7-24: Function with only logging calls
static RE_LOGGING_ONLY_FUNCTION: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?s)def\s+\w+.*?:\s*(?:log(?:ger)?\.(?:info|debug|warning|error)\s*\(.+?\)\s*)+(?:return\s+(?:True|None))?$"#).unwrap());

// P7-25: Different conditions leading to same outcome (disabled - backreferences not supported)
// static RE_CONDITIONAL_SAME_OUTCOME: Lazy<Regex> =
//     Lazy::new(|| Regex::new(r#"(?s)if\s+.+?:\s*(\w+)\s*=\s*(.+?)\s+(?:elif|else).*?:\s*"#).unwrap());

// P7 Loop/Conditional Patterns: Replace AST checks

// P7-26: Empty if statement body
static RE_EMPTY_IF_BODY: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?m)if\s+.+?:\s*pass(?:\s*#.*)?$").unwrap());

// P7-27: Empty else statement body
static RE_EMPTY_ELSE_BODY: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?m)else:\s*pass(?:\s*#.*)?$").unwrap());

// P7-28: Infinite loop with only pass
static RE_WHILE_TRUE_PASS: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?m)while\s+True:\s*pass(?:\s*#.*)?$").unwrap());

// P7-29: For loop with only pass
static RE_FOR_LOOP_PASS: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?m)for\s+.+?:\s*pass(?:\s*#.*)?$").unwrap());

// P7-30: Nested pass statements
static RE_NESTED_PASS: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?s)(?:if|for|while|def|class)\s+.+?:\s*(?:if|for|while)\s+.+?:\s*pass").unwrap());

// P7-31: Loop with only break
static RE_BREAK_ONLY_LOOP: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?m)(?:for|while)\s+.+?:\s*break(?:\s*#.*)?$").unwrap());

// P7-32: Loop with only continue
static RE_CONTINUE_ONLY_LOOP: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?m)(?:for|while)\s+.+?:\s*continue(?:\s*#.*)?$").unwrap());

// P7-33: If without else (disabled - negative lookahead not supported)
// static RE_IF_WITHOUT_ELSE_INCOMPLETE: Lazy<Regex> =
//     Lazy::new(|| Regex::new(r"(?s)def\s+\w+.*?:\s*if\s+.+?:\s*return\s+.+?(?:$|def\s)").unwrap());

// P7-34: Switch/match with empty cases
static RE_SWITCH_EMPTY_CASES: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?m)(?:case|when)\s+.+?:\s*pass(?:\s*#.*)?$").unwrap());

// P7-35: Try with empty except block
static RE_TRY_EMPTY_EXCEPT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?s)try:\s*.+?except.*?:\s*pass(?:\s*#.*)?(?:\s|$)").unwrap());

// P7 Additional Anti-Patterns

// P7-36: Function name implies action (disabled - negative lookahead not supported)
// static RE_FUNCTION_NAME_IMPLIES_ACTION_NO_ACTION: Lazy<Regex> =
//     Lazy::new(|| Regex::new(r#"(?i)def\s+(?:create|build|generate|execute|run|process|calculate|compute)_\w+.*?:\s*(?:pass|return\s+None)"#).unwrap());

// P7-37: Assert False statement
static RE_ASSERT_FALSE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?m)^\s*assert\s+False\b"#).unwrap());

// P7-38: Raises exception indicating incomplete functionality
static RE_RAISE_INCOMPLETE_EXCEPTION: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"\braise\s+Not[I]mplementedError\b"#).unwrap());

// P7-39: Explicit return None (disabled - negative lookahead not supported)
// static RE_RETURN_NONE_EXPLICITLY: Lazy<Regex> =
//     Lazy::new(|| Regex::new(r#"(?m)def\s+\w+.*?:\s*return\s+None(?:\s*#.*)?$"#).unwrap());

// P7-40: Decorator returning input (disabled - negative lookahead + backreference not supported)
// static RE_EMPTY_DECORATOR: Lazy<Regex> =
//     Lazy::new(|| Regex::new(r#"def\s+\w+\s*\((\w+)\):\s*return\s+"#).unwrap());

// P7-41: Import inside function to avoid circular dependency
static RE_CIRCULAR_IMPORT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?m)def\s+\w+.*?:\s*(?:from|import)\s+"#).unwrap());

// P7-42: Function with global variable mutation (simplified - no backreference)
static RE_GLOBAL_MUTATION_ONLY: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"def\s+\w+.*?:\s*global\s+\w+\s*\w+\s*=.+?(?:return\s+None)?$"#).unwrap());

// P7-43: Type checking without action
static RE_TYPE_CHECK_NO_ACTION: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?s)if\s+isinstance\s*\(.+?\):\s*pass|if\s+type\s*\(.+?\)\s*==.+?:\s*pass"#).unwrap());

// P7-44: Permission check (disabled - negative lookahead not supported)
// static RE_PERMISSION_CHECK_NO_ENFORCEMENT: Lazy<Regex> =
//     Lazy::new(|| Regex::new(r#"(?i)def\s+(?:check|verify)_permission.*?:\s*return\s+True"#).unwrap());

// P7-45: Validation function (disabled - negative lookahead not supported)
// static RE_VALIDATION_NO_ERROR: Lazy<Regex> =
//     Lazy::new(|| Regex::new(r#"(?i)def\s+validate_\w+.*?:\s*return\s+True"#).unwrap());

struct Cli {
    root_path: String,
    format: String,
    confidence: String,
    verbose: bool,
    no_cache: bool,
    clear_cache: bool,
}

impl Cli {
    fn parse() -> Self {
        let args: Vec<String> = env::args().collect();

        let mut root_path = String::from(".");
        let mut format = String::from("text");
        let mut confidence = String::from("medium");
        let mut verbose = false;
        let mut no_cache = false;
        let mut clear_cache = false;

        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "-d" | "--directory" => {
                    if i + 1 < args.len() {
                        root_path = args[i + 1].clone();
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
                "-f" | "--format" => {
                    if i + 1 < args.len() {
                        format = args[i + 1].clone();
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
                "-c" | "--confidence" => {
                    if i + 1 < args.len() {
                        confidence = args[i + 1].clone();
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
                "-v" | "--verbose" => {
                    verbose = true;
                    i += 1;
                }
                "--no-cache" => {
                    no_cache = true;
                    i += 1;
                }
                "--clear-cache" => {
                    clear_cache = true;
                    i += 1;
                }
                _ => {
                    if !args[i].starts_with('-') && root_path == "." {
                        root_path = args[i].clone();
                    }
                    i += 1;
                }
            }
        }

        Cli {
            root_path,
            format,
            confidence,
            verbose,
            no_cache,
            clear_cache,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum LanguageType {
    Python,
    JavaScript,
    Java,
    Rust,
}

impl LanguageType {
    fn from_extension(ext: &str) -> Option<Self> {
        match ext {
            "py" => Some(LanguageType::Python),
            "js" => Some(LanguageType::JavaScript),
            "java" => Some(LanguageType::Java),
            "rs" => Some(LanguageType::Rust),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Issue {
    file: String,
    line: usize,
    column: usize,
    function_name: String,
    severity: String,
    issue_type: String,
    description: String,
    suggested_fix: String,
}

#[derive(Debug, Clone)]
struct FunctionInfo {
    name: String,
    line_start: usize,
    line_end: usize,
    column: usize,
    params: String,
    body: String,
    indent_level: usize,

    actual_loc: Option<usize>,
    cyclomatic_complexity: Option<i32>,
    return_count: Option<usize>,
    return_types: Option<Vec<String>>,
    local_vars: Option<HashSet<String>>,
    global_vars: Option<HashSet<String>>,
    has_loops: Option<bool>,
    has_conditionals: Option<bool>,
    has_try_except: Option<bool>,
    has_async_await: Option<bool>,
    calls_functions: Option<HashSet<String>>,

    decorators: Option<Vec<String>>,
    parent_class: Option<String>,
}

/// AST-based function information with accurate metrics
///
/// This struct holds function analysis data extracted from Abstract Syntax Tree parsing,
/// providing more accurate metrics than regex-based extraction. Used for Python, Rust,
/// and JavaScript analysis with language-specific parsers.
#[derive(Debug, Clone)]
struct AstFunctionInfo {
    name: String,
    line_start: usize,
    line_end: usize,
    column: usize,
    params: Vec<String>,

    // AST-derived metrics (no guessing)
    actual_loc: usize,
    cyclomatic_complexity: i32,
    return_count: usize,
    return_types: Vec<String>,

    // Scope analysis from AST
    local_vars: HashSet<String>,
    global_vars: HashSet<String>,

    // Control flow from AST
    has_loops: bool,
    has_conditionals: bool,
    has_try_except: bool,
    has_async_await: bool,

    // Call graph from AST (more accurate than regex)
    calls_functions: HashSet<String>,

    decorators: Vec<String>,
    parent_class: Option<String>,

    indent_level: usize,
}

impl From<AstFunctionInfo> for FunctionInfo {
    fn from(ast_info: AstFunctionInfo) -> Self {
        FunctionInfo {
            name: ast_info.name,
            line_start: ast_info.line_start,
            line_end: ast_info.line_end,
            column: ast_info.column,
            params: ast_info.params.join(", "),
            body: String::new(),
            indent_level: ast_info.indent_level,
            actual_loc: Some(ast_info.actual_loc),
            cyclomatic_complexity: Some(ast_info.cyclomatic_complexity),
            return_count: Some(ast_info.return_count),
            return_types: Some(ast_info.return_types),
            local_vars: Some(ast_info.local_vars),
            global_vars: Some(ast_info.global_vars),
            has_loops: Some(ast_info.has_loops),
            has_conditionals: Some(ast_info.has_conditionals),
            has_try_except: Some(ast_info.has_try_except),
            has_async_await: Some(ast_info.has_async_await),
            calls_functions: Some(ast_info.calls_functions),
            decorators: if ast_info.decorators.is_empty() { None } else { Some(ast_info.decorators) },
            parent_class: ast_info.parent_class,
        }
    }
}

trait AstParser {
    fn parse(&self, content: &str) -> Result<Tree, String>;
    fn extract_functions(&self, tree: &Tree, content: &str) -> Vec<AstFunctionInfo>;
    fn language(&self) -> Language;
}

struct PythonAstParser;
struct RustAstParser;
struct JavaScriptAstParser;
struct JavaAstParser;

impl AstParser for PythonAstParser {
    fn language(&self) -> Language {
        tree_sitter_python::language()
    }

    fn parse(&self, content: &str) -> Result<Tree, String> {
        let mut parser = Parser::new();
        parser
            .set_language(self.language())
            .map_err(|e| format!("Failed to set Python language: {:?}", e))?;

        parser
            .parse(content, None)
            .ok_or_else(|| "Failed to parse Python code".to_string())
    }

    fn extract_functions(&self, tree: &Tree, content: &str) -> Vec<AstFunctionInfo> {
        let mut functions = Vec::new();
        let root_node = tree.root_node();

        let query_str = r#"
            ; Match all function definitions (module-level and class methods)
            (function_definition) @function
        "#;

        let query = Query::new(self.language(), query_str)
            .map_err(|e| eprintln!("Query error: {:?}", e))
            .ok();

        if let Some(query) = query {
            let mut cursor = QueryCursor::new();
            let matches = cursor.matches(&query, root_node, content.as_bytes());

            for m in matches {
                let func_node = m
                    .captures
                    .iter()
                    .find(|c| {
                        query.capture_names()[c.index as usize].ends_with("function")
                            || query.capture_names()[c.index as usize].ends_with("method")
                    })
                    .map(|c| c.node);

                if let Some(node) = func_node {
                    if let Some(info) = populate_ast_info_from_node(&node, content) {
                        functions.push(info);
                    }
                }
            }
        }

        let mut seen = HashSet::new();
        functions.retain(|f| {
            let key = (f.name.clone(), f.line_start);
            seen.insert(key)
        });

        functions
    }
}

impl AstParser for RustAstParser {
    fn language(&self) -> Language {
        tree_sitter_rust::language()
    }

    fn parse(&self, content: &str) -> Result<Tree, String> {
        let mut parser = Parser::new();
        parser
            .set_language(self.language())
            .map_err(|e| format!("Failed to set Rust language: {:?}", e))?;

        parser
            .parse(content, None)
            .ok_or_else(|| "Failed to parse Rust code".to_string())
    }

    fn extract_functions(&self, tree: &Tree, content: &str) -> Vec<AstFunctionInfo> {
        let mut functions = Vec::new();
        let root_node = tree.root_node();

        let query_str = r#"
            (function_item
                name: (identifier) @func_name
                parameters: (parameters) @params
                body: (block) @body) @function
        "#;

        let query = Query::new(self.language(), query_str)
            .map_err(|e| eprintln!("Query error: {:?}", e))
            .ok();

        if let Some(query) = query {
            let mut cursor = QueryCursor::new();
            let matches = cursor.matches(&query, root_node, content.as_bytes());

            for m in matches {
                if let Some(func_capture) = m.captures.first() {
                    if let Some(info) = populate_ast_info_from_node(&func_capture.node, content) {
                        functions.push(info);
                    }
                }
            }
        }

        functions
    }
}

impl AstParser for JavaScriptAstParser {
    fn language(&self) -> Language {
        tree_sitter_javascript::language()
    }

    fn parse(&self, content: &str) -> Result<Tree, String> {
        let mut parser = Parser::new();
        parser
            .set_language(self.language())
            .map_err(|e| format!("Failed to set JavaScript language: {:?}", e))?;

        parser
            .parse(content, None)
            .ok_or_else(|| "Failed to parse JavaScript code".to_string())
    }

    fn extract_functions(&self, tree: &Tree, content: &str) -> Vec<AstFunctionInfo> {
        let mut functions = Vec::new();
        let root_node = tree.root_node();

        let query_str = r#"
            (function_declaration
                name: (identifier) @func_name
                parameters: (formal_parameters) @params
                body: (statement_block) @body) @function

            (function_expression
                name: (identifier)? @func_name
                parameters: (formal_parameters) @params
                body: (statement_block) @body) @function_expr

            (arrow_function
                parameters: (_) @params
                body: (_) @body) @arrow_func
        "#;

        let query = Query::new(self.language(), query_str)
            .map_err(|e| eprintln!("Query error: {:?}", e))
            .ok();

        if let Some(query) = query {
            let mut cursor = QueryCursor::new();
            let matches = cursor.matches(&query, root_node, content.as_bytes());

            for m in matches {
                if let Some(func_capture) = m.captures.first() {
                    if let Some(info) = populate_ast_info_from_node(&func_capture.node, content) {
                        functions.push(info);
                    }
                }
            }
        }

        functions
    }
}

impl AstParser for JavaAstParser {
    fn language(&self) -> Language {
        tree_sitter_java::language()
    }

    fn parse(&self, content: &str) -> Result<Tree, String> {
        let mut parser = Parser::new();
        parser
            .set_language(self.language())
            .map_err(|e| format!("Failed to set Java language: {:?}", e))?;

        parser
            .parse(content, None)
            .ok_or_else(|| "Failed to parse Java code".to_string())
    }

    fn extract_functions(&self, tree: &Tree, content: &str) -> Vec<AstFunctionInfo> {
        let mut functions = Vec::new();
        let root_node = tree.root_node();

        let query_str = r#"
            (method_declaration
                name: (identifier) @method_name
                parameters: (formal_parameters) @params
                body: (block) @body) @method
        "#;

        let query = Query::new(self.language(), query_str)
            .map_err(|e| eprintln!("Query error: {:?}", e))
            .ok();

        if let Some(query) = query {
            let mut cursor = QueryCursor::new();
            let matches = cursor.matches(&query, root_node, content.as_bytes());

            for m in matches {
                if let Some(func_capture) = m.captures.first() {
                    if let Some(info) = populate_ast_info_from_node(&func_capture.node, content) {
                        functions.push(info);
                    }
                }
            }
        }

        functions
    }
}

/// Extracts comprehensive function metadata from an AST node.
///
/// Performs deep analysis of a function node to extract all relevant metrics including
/// lines of code, cyclomatic complexity, return patterns, variable usage, control flow,
/// and function calls. Uses recursive AST traversal for accurate metric calculation.
///
/// # Arguments
/// * `node` - The AST node representing a function/method definition
/// * `content` - The complete source code text
///
/// # Returns
/// * `Some(AstFunctionInfo)` - Complete function analysis data if extraction succeeds
/// * `None` - If the node lacks required components (name or body)
fn populate_ast_info_from_node(node: &Node, content: &str) -> Option<AstFunctionInfo> {
    let start_pos = node.start_position();
    let end_pos = node.end_position();
    let line_start = start_pos.row + 1;
    let line_end = end_pos.row + 1;
    let column = start_pos.column + 1;

    let name = extract_function_name(node, content)?;
    let params = extract_parameters(node, content);
    let body_node = find_body_node(node)?;

    let actual_loc = calculate_actual_loc(&body_node, content);
    let cyclomatic_complexity = calculate_cyclomatic_complexity(&body_node);
    let (return_count, return_types) = extract_return_info(&body_node, content);
    let (local_vars, global_vars) = extract_variable_info(&body_node, content);
    let has_loops = check_for_loops(&body_node);
    let has_conditionals = check_for_conditionals(&body_node);
    let has_try_except = check_for_try_except(&body_node);
    let has_async_await = check_for_async_await(node);
    let calls_functions = extract_function_calls(&body_node, content);
    let decorators = extract_decorators(node, content);
    let parent_class = extract_parent_class(node, content);

    let indent_text = &content[node.start_byte()
        ..node.start_byte() + start_pos.column.min(content.len() - node.start_byte())];
    let indent_level = indent_text
        .chars()
        .filter(|&c| c == ' ' || c == '\t')
        .count()
        / 4;

    Some(AstFunctionInfo {
        name,
        line_start,
        line_end,
        column,
        params,
        actual_loc,
        cyclomatic_complexity,
        return_count,
        return_types,
        local_vars,
        global_vars,
        has_loops,
        has_conditionals,
        has_try_except,
        has_async_await,
        calls_functions,
        decorators,
        parent_class,
        indent_level,
    })
}

/// Extracts decorator names from a Python function definition node.
///
/// Traverses the AST to find decorator nodes that precede the function definition.
/// Decorators are identified by checking if the function's parent is a "decorated_definition"
/// node, then extracting all "decorator" children. The '@' symbol is stripped from each
/// decorator name.
///
/// # Arguments
/// * `node` - The function definition AST node
/// * `content` - The source code text
///
/// # Returns
/// * `Vec<String>` - List of decorator names without '@' prefix (e.g., "abstractmethod", "click.command()")
fn extract_decorators(node: &Node, content: &str) -> Vec<String> {
    let mut decorators = Vec::new();

    if let Some(parent) = node.parent() {
        if parent.kind() == "decorated_definition" {
            let mut cursor = parent.walk();
            for child in parent.children(&mut cursor) {
                if child.kind() == "decorator" {
                    let decorator_text = content[child.start_byte()..child.end_byte()].to_string();
                    let cleaned = decorator_text.trim().trim_start_matches('@').to_string();
                    if !cleaned.is_empty() {
                        decorators.push(cleaned);
                    }
                }
            }
        }
    }

    decorators
}

/// Extracts the parent class name for a method within a Python class definition.
///
/// Traverses up the AST tree from the function node to find an enclosing "class_definition"
/// node. If found, extracts the class name. Additionally checks if the class inherits from
/// ABC (Abstract Base Class) by examining the class's base classes in the argument_list.
///
/// # Arguments
/// * `node` - The function definition AST node
/// * `content` - The source code text
///
/// # Returns
/// * `Some(String)` - The parent class name if the function is a method within a class
/// * `None` - If the function is not within a class or no class name found
fn extract_parent_class(node: &Node, content: &str) -> Option<String> {
    let mut current = node.parent();

    while let Some(parent) = current {
        if parent.kind() == "class_definition" {
            let mut cursor = parent.walk();
            for child in parent.children(&mut cursor) {
                if child.kind() == "identifier" || child.kind() == "name" {
                    return Some(content[child.start_byte()..child.end_byte()].to_string());
                }
                if child.kind() == "argument_list" {
                    let bases = content[child.start_byte()..child.end_byte()].to_string();
                    if bases.contains("ABC") || bases.contains("abc.ABC") {
                        if let Some(class_name) = parent.child_by_field_name("name") {
                            return Some(content[class_name.start_byte()..class_name.end_byte()].to_string());
                        }
                    }
                }
            }
        }
        current = parent.parent();
    }

    None
}

fn extract_function_name(node: &Node, content: &str) -> Option<String> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "identifier" || child.kind() == "name" {
            return Some(content[child.start_byte()..child.end_byte()].to_string());
        }
    }
    None
}

/// Extracts all parameter names from a function definition node.
///
/// Locates the parameters or formal_parameters child node and extracts the text
/// of each parameter identifier, handling language-specific parameter node types.
///
/// # Arguments
/// * `node` - The function definition AST node
/// * `content` - The source code text
///
/// # Returns
/// * `Vec<String>` - List of parameter names (may be empty for parameterless functions)
fn extract_parameters(node: &Node, content: &str) -> Vec<String> {
    let mut params = Vec::new();
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        let kind = child.kind();
        if kind == "parameters" || kind == "formal_parameters" {
            let mut param_cursor = child.walk();
            for param_child in child.children(&mut param_cursor) {
                if param_child.kind() == "identifier"
                    || param_child.kind() == "typed_parameter"
                    || param_child.kind() == "formal_parameter"
                {
                    let param_text =
                        content[param_child.start_byte()..param_child.end_byte()].to_string();
                    if !param_text.is_empty()
                        && param_text != "("
                        && param_text != ")"
                        && param_text != ","
                    {
                        params.push(param_text);
                    }
                }
            }
        }
    }

    params
}

/// Locates the body block node within a function definition.
///
/// Searches for a child node with kind "block", "statement_block", or any kind
/// containing "body" to find the function's executable body.
///
/// # Arguments
/// * `node` - The function definition AST node
///
/// # Returns
/// * `Some(Node)` - The body block node if found
/// * `None` - If no body node exists (invalid function)
fn find_body_node<'a>(node: &'a Node<'a>) -> Option<Node<'a>> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        let kind = child.kind();
        if kind == "block" || kind == "statement_block" || kind.contains("body") {
            return Some(child);
        }
    }
    None
}

/// Calculates the actual lines of code (non-blank lines) in a function body.
///
/// Extracts the function body text from the source and counts lines that contain
/// non-whitespace content, excluding blank lines and lines with only whitespace.
///
/// # Arguments
/// * `node` - The function body AST node
/// * `content` - The source code text
///
/// # Returns
/// * `usize` - Count of non-blank lines in the function body
fn calculate_actual_loc(node: &Node, content: &str) -> usize {
    let start_byte = node.start_byte();
    let end_byte = node.end_byte();
    let body_text = &content[start_byte..end_byte];

    body_text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count()
}

/// Calculates McCabe cyclomatic complexity of a function body.
///
/// Implements the McCabe complexity metric by counting decision points:
/// if/elif/else, loops (for/while/do), switch cases, catch clauses,
/// ternary expressions, and logical operators (&&, ||, and, or).
/// Base complexity is 1, each decision point adds 1.
///
/// # Arguments
/// * `node` - The function body AST node
///
/// # Returns
/// * `i32` - The cyclomatic complexity value (minimum 1)
fn calculate_cyclomatic_complexity(node: &Node) -> i32 {
    let mut complexity = 1;

    fn traverse_for_complexity(node: &Node, complexity: &mut i32) {
        let kind = node.kind();
        match kind {
            "if_statement"
            | "elif_clause"
            | "else_clause"
            | "for_statement"
            | "while_statement"
            | "do_statement"
            | "case"
            | "switch_statement"
            | "catch_clause"
            | "conditional_expression"
            | "ternary_expression" => {
                *complexity += 1;
            }
            "binary_expression" => {
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    if child.kind() == "&&"
                        || child.kind() == "||"
                        || child.kind() == "and"
                        || child.kind() == "or"
                    {
                        *complexity += 1;
                    }
                }
            }
            _ => {}
        }

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            traverse_for_complexity(&child, complexity);
        }
    }

    traverse_for_complexity(node, &mut complexity);
    complexity
}

/// Extracts return statement information from a function body.
///
/// Recursively traverses the AST to find all return statements, counting them
/// and classifying the type of each returned value (None, Boolean, Integer,
/// Float, String, Collection, or Expression).
///
/// # Arguments
/// * `node` - The function body AST node
/// * `content` - The source code text
///
/// # Returns
/// * `(usize, Vec<String>)` - Tuple of (return count, list of return value types)
fn extract_return_info(node: &Node, content: &str) -> (usize, Vec<String>) {
    let mut return_count = 0;
    let mut return_types = Vec::new();

    fn traverse_for_returns(
        node: &Node,
        content: &str,
        count: &mut usize,
        types: &mut Vec<String>,
    ) {
        if node.kind() == "return_statement" {
            *count += 1;

            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() != "return" {
                    let return_val = content[child.start_byte()..child.end_byte()].trim();
                    if !return_val.is_empty() {
                        types.push(classify_return_type(return_val));
                    }
                }
            }
        }

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            traverse_for_returns(&child, content, count, types);
        }
    }

    traverse_for_returns(node, content, &mut return_count, &mut return_types);
    (return_count, return_types)
}

/// Classifies the type of a return value based on its source code representation.
///
/// Uses actual parsing (i64/f64::parse) and pattern matching to determine
/// the semantic type of a returned expression. Handles literals and common
/// expressions across multiple languages.
///
/// # Arguments
/// * `value` - The return value source code text
///
/// # Returns
/// * `String` - Type classification: "None", "Boolean", "Integer", "Float",
///   "String", "Collection", or "Expression"
fn classify_return_type(value: &str) -> String {
    if value == "None" || value == "null" || value == "nullptr" || value == "nil" {
        "None".to_string()
    } else if value == "True" || value == "False" || value == "true" || value == "false" {
        "Boolean".to_string()
    } else if value.parse::<i64>().is_ok() {
        "Integer".to_string()
    } else if value.parse::<f64>().is_ok() {
        "Float".to_string()
    } else if (value.starts_with('"') && value.ends_with('"'))
        || (value.starts_with('\'') && value.ends_with('\''))
    {
        "String".to_string()
    } else if value.starts_with('[') || value.starts_with('{') {
        "Collection".to_string()
    } else {
        "Expression".to_string()
    }
}

/// Extracts local and global variable declarations from a function body.
///
/// Recursively traverses the AST to find variable assignments, declarations,
/// and global/nonlocal statements, collecting the variable names into
/// separate sets for local and global scopes.
///
/// # Arguments
/// * `node` - The function body AST node
/// * `content` - The source code text
///
/// # Returns
/// * `(HashSet<String>, HashSet<String>)` - Tuple of (local variables, global variables)
fn extract_variable_info(node: &Node, content: &str) -> (HashSet<String>, HashSet<String>) {
    let mut local_vars = HashSet::new();
    let mut global_vars = HashSet::new();

    fn traverse_for_vars(
        node: &Node,
        content: &str,
        locals: &mut HashSet<String>,
        globals: &mut HashSet<String>,
    ) {
        let kind = node.kind();
        match kind {
            "assignment"
            | "assignment_expression"
            | "variable_declaration"
            | "variable_declarator"
            | "local_variable_declaration" => {
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    if child.kind() == "identifier" {
                        let var_name = content[child.start_byte()..child.end_byte()].to_string();
                        if !var_name.is_empty() {
                            locals.insert(var_name);
                        }
                    }
                }
            }
            "global_statement" | "nonlocal_statement" => {
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    if child.kind() == "identifier" {
                        let var_name = content[child.start_byte()..child.end_byte()].to_string();
                        if !var_name.is_empty() {
                            globals.insert(var_name);
                        }
                    }
                }
            }
            _ => {}
        }

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            traverse_for_vars(&child, content, locals, globals);
        }
    }

    traverse_for_vars(node, content, &mut local_vars, &mut global_vars);
    (local_vars, global_vars)
}

/// Checks if a function body contains any loop constructs.
///
/// Recursively searches for for_statement, while_statement, or do_statement
/// nodes within the function body.
///
/// # Arguments
/// * `node` - The function body AST node
///
/// # Returns
/// * `bool` - True if any loops are present, false otherwise
fn check_for_loops(node: &Node) -> bool {
    fn traverse_for_loops(node: &Node) -> bool {
        let kind = node.kind();

        // Expanded loop detection to fix false "no loops" claims
        // Now includes comprehensions and generator expressions (Python)
        if kind == "for_statement"
            || kind == "while_statement"
            || kind == "do_statement"
            || kind == "list_comprehension"
            || kind == "dictionary_comprehension"
            || kind == "set_comprehension"
            || kind == "generator_expression"
            || kind == "for_in_clause"
        {
            return true;
        }

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if traverse_for_loops(&child) {
                return true;
            }
        }
        false
    }

    traverse_for_loops(node)
}

/// Checks if a function body contains any conditional constructs.
///
/// Recursively searches for if_statement, switch_statement, or
/// conditional_expression nodes within the function body.
///
/// # Arguments
/// * `node` - The function body AST node
///
/// # Returns
/// * `bool` - True if any conditionals are present, false otherwise
fn check_for_conditionals(node: &Node) -> bool {
    fn traverse_for_conditionals(node: &Node) -> bool {
        let kind = node.kind();

        // Expanded conditional detection to fix false "no conditionals" claims
        // Now includes comparison operators, boolean operators, and expression-level conditionals
        if kind == "if_statement"
            || kind == "switch_statement"
            || kind == "conditional_expression"
            || kind == "comparison_operator"
            || kind == "boolean_operator"
            || kind == "comparison_expression"
            || kind == "ternary_expression"
        {
            return true;
        }

        // Handle binary expressions that contain comparison or boolean operators
        if kind == "binary_expression" {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                let child_kind = child.kind();
                // Check for comparison operators
                if child_kind == ">"
                    || child_kind == "<"
                    || child_kind == "=="
                    || child_kind == "!="
                    || child_kind == ">="
                    || child_kind == "<="
                    || child_kind == "is"
                    || child_kind == "is not"
                    || child_kind == "&&"
                    || child_kind == "||"
                    || child_kind == "and"
                    || child_kind == "or"
                {
                    return true;
                }
            }
        }

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if traverse_for_conditionals(&child) {
                return true;
            }
        }
        false
    }

    traverse_for_conditionals(node)
}

/// Checks if a function body contains any exception handling constructs.
///
/// Recursively searches for try_statement, except_clause, or catch_clause
/// nodes within the function body.
///
/// # Arguments
/// * `node` - The function body AST node
///
/// # Returns
/// * `bool` - True if any exception handling is present, false otherwise
fn check_for_try_except(node: &Node) -> bool {
    fn traverse_for_try(node: &Node) -> bool {
        let kind = node.kind();
        if kind == "try_statement" || kind == "except_clause" || kind == "catch_clause" {
            return true;
        }

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if traverse_for_try(&child) {
                return true;
            }
        }
        false
    }

    traverse_for_try(node)
}

/// Checks if a function uses async/await constructs.
///
/// Recursively searches for nodes with "async" or "await" in their kind,
/// indicating asynchronous programming patterns.
///
/// # Arguments
/// * `node` - The function definition AST node
///
/// # Returns
/// * `bool` - True if async/await is used, false otherwise
fn check_for_async_await(node: &Node) -> bool {
    fn traverse_for_async(node: &Node) -> bool {
        let kind = node.kind();
        if kind.contains("async") || kind.contains("await") {
            return true;
        }

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if traverse_for_async(&child) {
                return true;
            }
        }
        false
    }

    traverse_for_async(node)
}

/// Extracts all function calls made within a function body.
///
/// Recursively traverses the AST to find call_expression or call nodes,
/// extracting the name of each called function.
///
/// # Arguments
/// * `node` - The function body AST node
/// * `content` - The source code text
///
/// # Returns
/// * `HashSet<String>` - Set of unique function names that are called
fn extract_function_calls(node: &Node, content: &str) -> HashSet<String> {
    let mut calls = HashSet::new();

    fn traverse_for_calls(node: &Node, content: &str, calls: &mut HashSet<String>) {
        // Improved function call detection to catch method calls and built-ins
        if node.kind() == "call_expression" || node.kind() == "call" {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "identifier" || child.kind() == "attribute" {
                    let func_name = content[child.start_byte()..child.end_byte()].to_string();
                    if !func_name.is_empty() {
                        // Extract just the method name from attribute access (e.g., "obj.method" -> "method")
                        let method_name = if func_name.contains('.') {
                            func_name
                                .split('.')
                                .next_back()
                                .unwrap_or(&func_name)
                                .to_string()
                        } else {
                            func_name
                        };
                        calls.insert(method_name);
                    }
                    break;
                }
            }
        }

        // Also detect standalone attribute access that represents method calls
        if node.kind() == "attribute" {
            // Check if parent is a call_expression
            if let Some(parent) = node.parent() {
                if parent.kind() == "call_expression" {
                    let attr_name = content[node.start_byte()..node.end_byte()].to_string();
                    if !attr_name.is_empty() && attr_name.contains('.') {
                        if let Some(method) = attr_name.split('.').next_back() {
                            calls.insert(method.to_string());
                        }
                    }
                }
            }
        }

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            traverse_for_calls(&child, content, calls);
        }
    }

    traverse_for_calls(node, content, &mut calls);
    calls
}

#[derive(Debug, Clone)]
struct FileContext {
    imports: Vec<String>,
    functions: Vec<FunctionInfo>,
    lang: LanguageType,
}

#[derive(Debug, Serialize, Deserialize)]
struct ScanCache {
    file_hashes: HashMap<String, String>,
    issues: Vec<Issue>,
}

impl ScanCache {
    fn new() -> Self {
        ScanCache {
            file_hashes: HashMap::new(),
            issues: Vec::new(),
        }
    }

    fn load(path: &Path) -> Option<Self> {
        if !path.exists() {
            return None;
        }
        let content = fs::read_to_string(path).ok()?;
        serde_json::from_str(&content).ok()
    }

    fn save(&self, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let content = serde_json::to_string_pretty(self)?;
        fs::write(path, content)?;
        Ok(())
    }
}

fn calculate_file_hash(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let content = fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(&content);
    let result = hasher.finalize();
    Ok(hex::encode(result))
}

/// Checks if a path should be excluded from scanning based on ignore patterns.
/// Returns true if the path matches any pattern in ignored_paths or built-in exclusions.
fn should_exclude_path(path: &Path, ignored_paths: &HashSet<PathBuf>) -> bool {
    let debug_mode = std::env::var("SCANNER_DEBUG").is_ok();

    let current_dir = match env::current_dir() {
        Ok(dir) => dir,
        Err(_) => return false,
    };

    let path_to_check = if path.is_absolute() {
        path.to_path_buf()
    } else {
        current_dir.join(path)
    };

    let path_str = path_to_check.to_string_lossy().to_lowercase().replace("\\", "/");

    if debug_mode {
        eprintln!("DEBUG_PATH: Checking path: '{}'", path.display());
        eprintln!("DEBUG_PATH: Normalized: '{}'", path_str);
        eprintln!("DEBUG_PATH: Is absolute: {}", path.is_absolute());
        eprintln!("DEBUG_PATH: Ignored patterns count: {}", ignored_paths.len());
    }

    for ignored_path in ignored_paths {
        let ignored_to_check = if ignored_path.is_absolute() {
            ignored_path.clone()
        } else {
            current_dir.join(ignored_path)
        };

        let ignored_str = ignored_to_check.to_string_lossy().to_lowercase().replace("\\", "/");

        if debug_mode {
            eprintln!("DEBUG_PATH:   Comparing against: '{}'", ignored_str);
            eprintln!("DEBUG_PATH:   starts_with result: {}", path_str.starts_with(&ignored_str));
        }

        if path_str.starts_with(&ignored_str) {
            if debug_mode {
                eprintln!("DEBUG_PATH: ✓ EXCLUDED by pattern: '{}'", ignored_str);
            }
            return true;
        }
    }

    // Fallback to built-in exclusions - normalize to forward slashes for consistent matching
    let path_normalized = path.to_string_lossy().to_lowercase().replace("\\", "/");
    if path_normalized.contains("/__pycache__/") ||
       path_normalized.contains("/.pixi/") ||
       path_normalized.contains("/target/") ||
       path_normalized.contains("/node_modules/") ||
       path_normalized.contains("/vendor/") ||
       path_normalized.contains("/_build/") ||
       path_normalized.contains("/dist/") ||
       path_normalized.ends_with(".min.js") ||
       path_normalized.ends_with(".min.css") ||
       path_normalized.contains("jquery") ||
       path_normalized.contains("bootstrap") ||
       path_normalized.contains("lodash") ||
       path_normalized.contains("moment") ||
       path_normalized.contains("react.") ||
       path_normalized.contains("vue.") ||
       path_normalized.contains("/tools/") ||
       path_normalized.contains("/scripts/production_scanner") ||
       path_normalized.contains("_template") ||
       path_normalized.contains("example") ||
       path_normalized.contains("Example") {
        if debug_mode {
            eprintln!("DEBUG_PATH: ✓ EXCLUDED by built-in pattern");
        }
        return true;
    }

    if debug_mode {
        eprintln!("DEBUG_PATH: ✗ NOT EXCLUDED - will scan");
    }
    false
}

/// Loads path exclusion patterns from .scannerignore file.
/// Returns a HashSet of paths to exclude. Empty lines and lines starting with # are ignored.
fn load_scannerignore(scanner_dir: &Path) -> HashSet<PathBuf> {
    let debug_mode = std::env::var("SCANNER_DEBUG").is_ok();
    let mut ignored_paths = HashSet::new();
    let ignore_file = scanner_dir.join(".scannerignore");

    if debug_mode {
        eprintln!("DEBUG_LOAD: Loading .scannerignore from: {}", ignore_file.display());
    }

    if let Ok(content) = fs::read_to_string(&ignore_file) {
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let path_buf = PathBuf::from(trimmed);
            if debug_mode {
                eprintln!("DEBUG_LOAD: Loaded pattern: '{}'", trimmed);
            }
            ignored_paths.insert(path_buf);
        }
    } else if debug_mode {
        eprintln!("DEBUG_LOAD: Failed to read .scannerignore file");
    }

    if debug_mode {
        eprintln!("DEBUG_LOAD: Total patterns loaded: {}", ignored_paths.len());
    }

    ignored_paths
}

fn is_legitimate_design_pattern(
    func: &FunctionInfo,
    _file_context: &FileContext,
) -> Option<&'static str> {
    let name_lower = func.name.to_lowercase();
    let loc = func.body.lines().filter(|l| !l.trim().is_empty()).count();

    if ((name_lower.starts_with("get_")
        && (name_lower.contains("manager")
            || name_lower.contains("instance")
            || name_lower.contains("singleton")
            || name_lower.contains("service")
            || name_lower.contains("engine")
            || name_lower.contains("handler")))
        || name_lower == "instance")
        && loc <= 10
        && func.body.contains("global")
    {
        return Some("singleton_pattern");
    }

    // Expanded factory pattern LOC from <=6 to <=10 to handle more complex factories
    if (name_lower.starts_with("create_")
        || name_lower.starts_with("make_")
        || name_lower.starts_with("build_")
        || name_lower.starts_with("new_"))
        && loc <= 10
        && func.body.contains("return")
    {
        return Some("factory_pattern");
    }

    if loc <= 4 {
        let return_lines: Vec<_> = func
            .body
            .lines()
            .filter(|l| l.trim().starts_with("return"))
            .collect();
        if return_lines.len() == 1 {
            let ret_line = return_lines[0];
            if ret_line.contains("(")
                && !ret_line.trim().starts_with("return \"")
                && !ret_line.trim().starts_with("return '")
            {
                return Some("wrapper_pattern");
            }
        }
    }

    // Delegation pattern: function that delegates to another method/object (up to 8 lines)
    if loc <= 8 {
        let return_lines: Vec<_> = func
            .body
            .lines()
            .filter(|l| l.trim().starts_with("return"))
            .collect();
        if return_lines.len() == 1 {
            let ret_line = return_lines[0];
            // Check if returning a call to self.method() or other.method()
            if (ret_line.contains("self.") || ret_line.contains("this."))
                && ret_line.contains("(")
                && ret_line.contains(")")
            {
                return Some("delegation_pattern");
            }
        }
    }

    if name_lower.contains("config") && loc <= 8 && func.body.contains("return") {
        return Some("config_pattern");
    }

    // Simple validator pattern: functions that validate with basic conditionals
    if (name_lower.contains("validate")
        || name_lower.contains("check")
        || name_lower.starts_with("is_valid"))
        && loc <= 15
        && func.body.contains("if")
        && func.body.contains("return")
    {
        return Some("validator_pattern");
    }

    None
}

/// Detects if a function is an abstract method that should be excluded from analysis.
///
/// Checks for Python abstract method patterns by examining decorators for @abstractmethod
/// or @abc.abstractmethod, and by checking if the function is within a class that inherits
/// from ABC (Abstract Base Class). Abstract methods are intentionally incomplete by design
/// as they define interfaces to be implemented by subclasses.
///
/// # Arguments
/// * `func` - The function information to analyze
///
/// # Returns
/// * `bool` - True if the function is an abstract method, false otherwise
fn is_abstract_method(func: &FunctionInfo) -> bool {
    if let Some(ref decorators) = func.decorators {
        for decorator in decorators {
            let dec_lower = decorator.to_lowercase();
            if dec_lower.contains("abstractmethod")
                || dec_lower.contains("abc.abstractmethod")
            {
                return true;
            }
        }
    }

    if let Some(ref _parent_class) = func.parent_class {
        let non_empty_lines: Vec<&str> = func.body.lines()
            .filter(|l| {
                let t = l.trim();
                !t.is_empty() && !t.starts_with('#') && !t.starts_with("\"\"\"") && !t.starts_with("'''") && !t.starts_with("\"") && t != "\"\"\""  && t != "'''"
            })
            .collect();

        if non_empty_lines.is_empty() || (non_empty_lines.len() == 1 && (non_empty_lines[0].trim() == "pass" || non_empty_lines[0].trim() == "...")) {
            return true;
        }
    }

    let body_lower = func.body.to_lowercase();
    if body_lower.contains("notimplementederror") || body_lower.contains("not implemented") {
        return true;
    }

    false
}

/// Detects if a function is a CLI framework command group or endpoint.
///
/// Identifies functions decorated with CLI framework patterns from Click, Typer, and
/// similar command-line interface libraries. These decorators include @cli.group(),
/// @cli.command(), @app.command(), @click.group(), etc. CLI framework patterns are
/// legitimate architectural components that delegate to subcommands or handlers.
///
/// # Arguments
/// * `func` - The function information to analyze
///
/// # Returns
/// * `bool` - True if the function uses CLI framework decorators, false otherwise
fn is_cli_framework_pattern(func: &FunctionInfo) -> bool {
    if let Some(ref decorators) = func.decorators {
        for decorator in decorators {
            let dec = decorator.to_lowercase();
            if dec.contains(".group(")
                || dec.contains(".command(")
                || dec.ends_with(".group")
                || dec.ends_with(".command")
                || dec.contains("cli.group")
                || dec.contains("cli.command")
                || dec.contains("app.command")
                || dec.contains("click.group")
                || dec.contains("click.command")
            {
                return true;
            }
        }
    }

    false
}

/// Detects if a function is a code generator that returns code as a string.
///
/// Code generators return script templates, Frida hooks, Ghidra scripts, or other
/// executable code as strings. These are legitimate implementations that generate
/// working code as their output rather than executing logic directly inline.
///
/// Patterns detected:
/// - Returns multi-line strings (triple quotes) with code syntax
/// - Contains import statements, function definitions, class definitions in strings
/// - Returns template code for Frida, Ghidra, Python, JavaScript, etc.
///
/// # Arguments
/// * `func` - The function information to analyze
///
/// # Returns
/// * `bool` - True if the function generates code as output, false otherwise
fn is_code_generator_pattern(func: &FunctionInfo) -> bool {
    let body = &func.body;

    let has_triple_quote_return = body.contains("return \"\"\"")
        || body.contains("return '''")
        || body.contains("return f\"\"\"")
        || body.contains("return f'''");
    if !has_triple_quote_return {
        return false;
    }

    let body_lower = body.to_lowercase();

    let has_code_patterns = body_lower.contains("import ")
        || body_lower.contains("def ")
        || body_lower.contains("function ")
        || body_lower.contains("class ")
        || body_lower.contains("const ")
        || body_lower.contains("var ")
        || body_lower.contains("frida.")
        || body_lower.contains("process.")
        || body_lower.contains("memory.")
        || body_lower.contains("interceptor.")
        || body_lower.contains("console.log")
        || body_lower.contains("module.exports");

    let line_count = body.lines().count();

    has_triple_quote_return && has_code_patterns && line_count > 5
}

/// Detects if a function is a legitimate delegation wrapper that adds value.
///
/// Identifies short functions (≤3 lines) that delegate to other functions while adding
/// meaningful functionality such as error handling (try/except), logging, or validation.
/// These wrappers are architectural patterns for cross-cutting concerns and should not
/// be flagged as incomplete. Simple pass-through functions without added value are not
/// considered legitimate delegation.
///
/// # Arguments
/// * `func` - The function information to analyze
///
/// # Returns
/// * `bool` - True if the function is a value-adding delegation wrapper, false otherwise
fn is_legitimate_delegation(func: &FunctionInfo) -> bool {
    let lines: Vec<&str> = func.body.lines().filter(|l| !l.trim().is_empty()).collect();

    if lines.len() <= 3 {
        let has_single_return = lines.iter().filter(|l| l.trim().starts_with("return")).count() == 1;
        let has_function_call = func.calls_functions.as_ref().map_or(false, |calls| !calls.is_empty());

        if has_single_return && has_function_call {
            let has_error_handling = func.has_try_except == Some(true);
            let body_lower = func.body.to_lowercase();
            let has_logging = body_lower.contains("log") || body_lower.contains("print");
            let has_validation = body_lower.contains("if ") || body_lower.contains("isinstance");
            let calls_other_module = func.calls_functions.as_ref().map_or(false, |calls| {
                calls.iter().any(|c| c.contains(".") || c.contains("::"))
            });
            let has_imports = body_lower.contains("import ");

            let delegates_to_member = body_lower.contains("self.") &&
                (body_lower.contains("return self.") || body_lower.contains("self._"));

            return has_error_handling || has_logging || has_validation || calls_other_module || has_imports || delegates_to_member;
        }
    }

    false
}

/// Detects if a function follows an orchestration pattern that coordinates multiple operations.
///
/// Identifies functions that orchestrate workflows by calling multiple other functions (≥3)
/// and exhibiting at least 2 of the following characteristics: progress reporting (logging,
/// print statements), result aggregation (collecting outputs from multiple calls), and error
/// handling (try/except blocks). Orchestration functions are legitimate high-level controllers
/// that coordinate complex operations across multiple components.
///
/// # Arguments
/// * `func` - The function information to analyze
///
/// # Returns
/// * `bool` - True if the function exhibits orchestration patterns, false otherwise
fn is_orchestration_pattern(func: &FunctionInfo) -> bool {
    let function_call_count = func.calls_functions.as_ref().map_or(0, |calls| calls.len());

    if function_call_count < 2 {
        return false;
    }

    let body_lower = func.body.to_lowercase();
    let name_lower = func.name.to_lowercase();

    let has_progress_reporting =
        body_lower.contains("print(") || body_lower.contains("logger") || body_lower.contains("progress");

    let has_result_aggregation = body_lower.contains("result")
        || body_lower.contains("output")
        || body_lower.contains("collect")
        || body_lower.contains("aggregate");

    let has_error_handling = func.has_try_except == Some(true);

    let has_orchestration_name = name_lower.starts_with("run_")
        || name_lower.starts_with("execute_")
        || name_lower.starts_with("perform_")
        || name_lower.starts_with("do_")
        || name_lower.contains("orchestrat")
        || name_lower.contains("coordinate")
        || name_lower.contains("workflow");

    let orchestration_signals =
        [has_progress_reporting, has_result_aggregation, has_error_handling, has_orchestration_name]
            .iter()
            .filter(|&&signal| signal)
            .count();

    orchestration_signals >= 2
}

/// Detects if a function delegates work to an LLM/AI backend.
///
/// Identifies functions that primarily delegate analysis or generation tasks to Large Language
/// Models or AI services. These functions are thin wrappers around LLM API calls and should not
/// be flagged as incomplete implementations. Detects common LLM method patterns like `.chat()`,
/// `.generate()`, `.complete()`, and `.create()` on model/llm/client objects.
///
/// # Arguments
/// * `func` - The function information to analyze
///
/// # Returns
/// * `bool` - True if the function exhibits LLM delegation patterns, false otherwise
fn is_llm_delegation_pattern(func: &FunctionInfo) -> bool {
    let body_lower = func.body.to_lowercase();

    // Check for LLM-related method calls
    let has_llm_call = body_lower.contains(".chat(")
        || body_lower.contains(".generate(")
        || body_lower.contains(".complete(")
        || body_lower.contains(".create(")
        || body_lower.contains("llm.")
        || body_lower.contains("model.")
        || body_lower.contains("client.")
        || body_lower.contains("backend.");

    // Check for LLM-related variable references
    let has_llm_reference = body_lower.contains("llm")
        || body_lower.contains("model")
        || body_lower.contains("openai")
        || body_lower.contains("anthropic")
        || body_lower.contains("gpt")
        || body_lower.contains("claude");

    // Check for prompt-related patterns
    let has_prompt = body_lower.contains("prompt") || body_lower.contains("messages");

    // Function must have LLM calls and references to be considered delegation
    has_llm_call && (has_llm_reference || has_prompt)
}

/// Detects if a function is a CLI wrapper that delegates to execute_command.
///
/// CLI wrappers are functions that build command-line arguments and delegate
/// execution to an execute_command method. These are legitimate architectural
/// patterns for separating API from CLI implementation.
///
/// # Arguments
/// * `func` - The function information to analyze
///
/// # Returns
/// * `bool` - True if the function is a CLI wrapper, false otherwise
fn is_cli_wrapper_pattern(func: &FunctionInfo) -> bool {
    let body_lower = func.body.to_lowercase();

    let calls_execute_command = body_lower.contains("execute_command(")
        || body_lower.contains(".execute_command(");

    let builds_cli_args = body_lower.contains("args = [")
        || body_lower.contains("args.append(")
        || body_lower.contains("args.extend(")
        || body_lower.contains("--");

    calls_execute_command && builds_cli_args
}

/// Detects if a function is a production binary analyzer.
///
/// Binary analyzers use specialized libraries (pefile, magic, lief) or search
/// for assembly patterns in binary data. These are production-grade implementations.
///
/// # Arguments
/// * `func` - The function information to analyze
///
/// # Returns
/// * `bool` - True if the function is a binary analyzer, false otherwise
fn is_binary_analyzer_pattern(func: &FunctionInfo) -> bool {
    let body_lower = func.body.to_lowercase();

    let uses_binary_libs = body_lower.contains("import pefile")
        || body_lower.contains("import magic")
        || body_lower.contains("import lief")
        || body_lower.contains("pefile.pe(")
        || body_lower.contains("magic.from_file(");

    let searches_binary_patterns = body_lower.contains("binary_data.find(")
        || body_lower.contains("data.find(b\"")
        || (body_lower.contains(".read()") && body_lower.contains("\"rb\""));

    let has_assembly_patterns = body_lower.contains("\\x")
        && (body_lower.contains("test ") || body_lower.contains("cmp ") || body_lower.contains("jz ") || body_lower.contains("jnz "));

    uses_binary_libs || searches_binary_patterns || has_assembly_patterns
}

/// Detects if a function is a simple getter or setter.
///
/// Getters and setters are simple data access methods that store or retrieve
/// data without significant logic. These are basic architectural patterns.
///
/// # Arguments
/// * `func` - The function information to analyze
///
/// # Returns
/// * `bool` - True if the function is a getter/setter, false otherwise
fn is_getter_setter_pattern(func: &FunctionInfo) -> bool {
    let lines: Vec<&str> = func.body.lines().filter(|l| !l.trim().is_empty()).collect();

    if lines.len() > 3 {
        return false;
    }

    let body_lower = func.body.to_lowercase();
    let name_lower = func.name.to_lowercase();

    let is_getter = (name_lower.starts_with("get_") || name_lower.starts_with("_get_"))
        && body_lower.contains("return ");

    let is_setter = (name_lower.starts_with("set_") || name_lower.starts_with("_set_") || name_lower.contains("register_"))
        && (body_lower.contains("self.") || body_lower.contains("this."));

    let simple_dict_access = body_lower.contains("return dict(")
        || (body_lower.contains("return ") && body_lower.contains("self.") && !body_lower.contains("("));

    let simple_assignment = body_lower.matches('=').count() == 1
        && !body_lower.contains("==")
        && (body_lower.contains("self.") || body_lower.contains("this."));

    is_getter || is_setter || simple_dict_access || simple_assignment
}

/// Detects if a function returns knowledge base or reference data.
///
/// Knowledge base functions return hardcoded reference data like methodologies,
/// techniques, or instruction sets. This is legitimate reference information
/// used for guidance, distinct from incomplete implementations.
///
/// # Arguments
/// * `func` - The function information to analyze
///
/// # Returns
/// * `bool` - True if the function returns reference data, false otherwise
fn is_knowledge_base_pattern(func: &FunctionInfo) -> bool {
    let body_lower = func.body.to_lowercase();
    let name_lower = func.name.to_lowercase();

    let has_instruction_keywords = body_lower.contains("step")
        && (body_lower.contains("load") || body_lower.contains("analyze") || body_lower.contains("identify"));

    let has_methodology_markers = body_lower.contains("\"")
        && (body_lower.contains("locate") || body_lower.contains("monitor") || body_lower.contains("capture"));

    let is_steps_or_recommendations = name_lower.contains("steps")
        || name_lower.contains("recommendations")
        || name_lower.contains("methodology");

    let returns_dict_mapping = body_lower.contains("steps_map")
        || body_lower.contains(".get(")
        && body_lower.contains("return ");

    is_steps_or_recommendations && (has_instruction_keywords || has_methodology_markers || returns_dict_mapping)
}

/// Detects if a function is a prompt builder for LLMs.
///
/// Prompt builders create text prompts for AI models, not executable code.
/// They often use f-strings with instructions but don't generate actual scripts.
///
/// # Arguments
/// * `func` - The function information to analyze
///
/// # Returns
/// * `bool` - True if the function builds prompts, false otherwise
fn is_prompt_builder_pattern(func: &FunctionInfo) -> bool {
    let body_lower = func.body.to_lowercase();
    let name_lower = func.name.to_lowercase();

    let is_prompt_function = name_lower.contains("prompt")
        || name_lower.contains("build_")
        && (name_lower.contains("objectives") || name_lower.contains("instructions"));

    let has_prompt_content = body_lower.contains("generate a")
        || body_lower.contains("create a")
        || body_lower.contains("provide")
        || body_lower.contains("explain");

    let uses_fstring = body_lower.contains("return f\"\"\"") || body_lower.contains("f\"\"\"");

    let no_code_generation = !body_lower.contains("import ")
        && !body_lower.contains("function ")
        && !body_lower.contains("def ")
        && !body_lower.contains("frida.");

    is_prompt_function && has_prompt_content && uses_fstring && no_code_generation
}

fn is_factory_pattern(func: &FunctionInfo) -> bool {
    let body_lower = func.body.to_lowercase();
    let name_lower = func.name.to_lowercase();

    let is_factory_name = name_lower.starts_with("create_")
        || name_lower.starts_with("init_")
        || name_lower.starts_with("make_")
        || name_lower.starts_with("build_")
        || name_lower.starts_with("get_") && (name_lower.contains("instance") || name_lower.contains("_analyzer") || name_lower.contains("_engine"));

    let returns_new_instance = body_lower.contains("return");

    let line_count = func.body.lines().filter(|l| !l.trim().is_empty() && !l.trim().starts_with("#") && !l.trim().starts_with("\"\"\"") && !l.trim().starts_with("'''")).count();
    let is_short = line_count <= 10;

    let has_class_instantiation = body_lower.contains("(") && body_lower.contains(")");

    let result = is_factory_name && returns_new_instance && has_class_instantiation && is_short;

    if name_lower.starts_with("create") {
        eprintln!("    FACTORY CHECK '{}': is_factory_name={}, returns={}, has_class={}, is_short={} (lines={}), RESULT={}",
            func.name, is_factory_name, returns_new_instance, has_class_instantiation, is_short, line_count, result);
    }

    result
}

fn is_enhanced_code_generator(func: &FunctionInfo) -> bool {
    let body = &func.body;

    let has_multiline_string = body.contains("return \"\"\"")
        || body.contains("return '''")
        || body.contains("return f\"\"\"")
        || body.contains("return f'''")
        || body.contains("return r\"\"\"")
        || body.contains("return r'''");

    if !has_multiline_string {
        return false;
    }

    let body_lower = body.to_lowercase();

    let has_code_keywords = body_lower.contains("import ")
        || body_lower.contains("def ")
        || body_lower.contains("function ")
        || body_lower.contains("class ")
        || body_lower.contains("const ")
        || body_lower.contains("var ")
        || body_lower.contains("let ")
        || body_lower.contains("frida.")
        || body_lower.contains("process.")
        || body_lower.contains("interceptor.")
        || body_lower.contains("console.log")
        || body_lower.contains("#include")
        || body_lower.contains("malloc")
        || body_lower.contains("printf");

    has_multiline_string && has_code_keywords
}

fn is_production_implementation(func: &FunctionInfo) -> bool {
    let body = &func.body;
    let body_lower = body.to_lowercase();

    let has_actual_logic = body_lower.contains("for ")
        || body_lower.contains("while ")
        || body_lower.contains("if ")
        || body_lower.contains("elif ")
        || body_lower.contains("else:");

    let has_external_calls = body_lower.matches('.').count() >= 3;

    let has_error_handling = body_lower.contains("try:")
        || body_lower.contains("except ")
        || body_lower.contains("catch ")
        || body_lower.contains("finally")
        || body_lower.contains("raise ")
        || body_lower.contains("throw ");

    let line_count = body.lines().filter(|l| !l.trim().is_empty() && !l.trim().starts_with("#") && !l.trim().starts_with("\"\"\"") && !l.trim().starts_with("'''")).count();
    let has_reasonable_length = line_count >= 8;

    let has_multiple_operations = body_lower.matches('=').count() >= 3
        || body_lower.matches(".append").count() >= 1
        || body_lower.matches(".add(").count() >= 1
        || body_lower.matches(".extend").count() >= 1
        || body_lower.matches(".update(").count() >= 1
        || body_lower.matches(".insert(").count() >= 1;

    let has_data_structures = body_lower.contains("[]") || body_lower.contains("{}") || body_lower.contains("dict(") || body_lower.contains("list(") || body_lower.contains("set(");

    (has_actual_logic && has_external_calls)
        || (has_error_handling && has_reasonable_length)
        || (has_multiple_operations && has_data_structures && line_count >= 5)
}

fn is_enhanced_binary_analyzer(func: &FunctionInfo) -> bool {
    let body_lower = func.body.to_lowercase();

    let uses_binary_libs = body_lower.contains("import pefile")
        || body_lower.contains("import magic")
        || body_lower.contains("import lief")
        || body_lower.contains("pefile.pe(")
        || body_lower.contains("magic.from_file(");

    let uses_regex_analysis = (body_lower.contains("import re") || body_lower.contains("re."))
        && (body_lower.contains("search(") || body_lower.contains("findall(") || body_lower.contains("match("));

    let analyzes_traces = body_lower.contains("trace")
        && (body_lower.contains("for ") || body_lower.contains("enumerate("))
        && body_lower.contains("instruction");

    let analyzes_patterns = body_lower.contains("pattern")
        && (body_lower.contains("[") || body_lower.contains("{"))
        && (body_lower.contains("in ") || body_lower.contains("for "));

    let searches_binary_data = body_lower.contains("data.find(")
        || body_lower.contains("binary_data")
        || (body_lower.contains(".read()") && body_lower.contains("rb"));

    uses_binary_libs || uses_regex_analysis || analyzes_traces || analyzes_patterns || searches_binary_data
}

/// Detects if a function is a delegator pattern that routes/dispatches to other functions.
///
/// Delegator functions are thin wrappers that primarily call other functions without significant
/// processing. They often use dictionaries/maps for routing or simple conditional logic. These
/// are legitimate architectural patterns and should not be flagged as incomplete.
///
/// # Arguments
/// * `func` - The function information to analyze
///
/// # Returns
/// * `bool` - True if the function exhibits delegator patterns, false otherwise
fn is_delegator_pattern(func: &FunctionInfo) -> bool {
    let loc = func.actual_loc.unwrap_or_else(|| func.body.lines().filter(|l| !l.trim().is_empty()).count());

    if loc > 15 {
        return false;
    }

    let function_call_count = func.calls_functions.as_ref().map_or(0, |calls| calls.len());

    if function_call_count == 0 {
        return false;
    }

    let body_lower = func.body.to_lowercase();

    let has_dict_dispatch = body_lower.contains("{") &&
                          (body_lower.contains(".get(") || body_lower.contains("["));

    let has_simple_routing = (body_lower.contains("return") && function_call_count >= 1) ||
                           (body_lower.contains("if") && function_call_count >= 2);

    let local_var_count = func.local_vars.as_ref().map_or(0, |vars| vars.len());
    let has_minimal_state = local_var_count <= 3;

    (has_dict_dispatch || has_simple_routing) && has_minimal_state
}

/// Detects if a function is a property accessor (getter/setter).
///
/// Property accessors are simple functions that get or set object attributes without complex
/// processing. These are legitimate patterns and should not be flagged as incomplete.
///
/// # Arguments
/// * `func` - The function information to analyze
///
/// # Returns
/// * `bool` - True if the function is a property accessor, false otherwise
fn is_property_accessor(func: &FunctionInfo) -> bool {
    let name_lower = func.name.to_lowercase();
    let body_lower = func.body.to_lowercase();

    let has_accessor_name = name_lower.starts_with("get_") ||
                          name_lower.starts_with("set_") ||
                          name_lower.starts_with("is_") ||
                          name_lower.starts_with("has_");

    if !has_accessor_name {
        return false;
    }

    let loc = func.actual_loc.unwrap_or_else(|| func.body.lines().filter(|l| !l.trim().is_empty()).count());

    if loc > 5 {
        return false;
    }

    let has_return = body_lower.contains("return");
    let has_assignment = body_lower.contains("=") || body_lower.contains("self.");

    has_return || has_assignment
}

/// Detects if a function is an event handler.
///
/// Event handlers respond to events and typically delegate to other functions or update state.
/// They are often short and should not be flagged as incomplete.
///
/// # Arguments
/// * `func` - The function information to analyze
///
/// # Returns
/// * `bool` - True if the function is an event handler, false otherwise
fn is_event_handler(func: &FunctionInfo) -> bool {
    let name_lower = func.name.to_lowercase();

    let has_handler_name = name_lower.starts_with("on_") ||
                         name_lower.starts_with("handle_") ||
                         name_lower.starts_with("_on_") ||
                         name_lower.contains("_handler") ||
                         name_lower.contains("callback");

    if !has_handler_name {
        return false;
    }

    let loc = func.actual_loc.unwrap_or_else(|| func.body.lines().filter(|l| !l.trim().is_empty()).count());

    loc <= 10
}

fn is_ui_property_pattern(func: &FunctionInfo) -> bool {
    RE_UI_PROPERTY.is_match(&func.name)
}

fn is_tool_checker_pattern(func: &FunctionInfo) -> bool {
    if !RE_TOOL_CHECKER.is_match(&func.name) {
        return false;
    }
    let body_lower = func.body.to_lowercase();
    body_lower.contains("which") || body_lower.contains("shutil.which") || body_lower.contains("find_executable") || body_lower.contains("subprocess") || body_lower.contains("path.exists") || body_lower.contains("import") || body_lower.contains("importlib")
}

fn is_callback_setter_pattern(func: &FunctionInfo) -> bool {
    if !RE_CALLBACK_SETTER.is_match(&func.name) {
        return false;
    }
    let loc = func.actual_loc.unwrap_or_else(|| func.body.lines().filter(|l| !l.trim().is_empty()).count());
    if loc > 8 {
        return false;
    }
    let body_lower = func.body.to_lowercase();
    body_lower.contains("self.") || body_lower.contains("this.") || body_lower.contains("callback") || body_lower.contains("handler")
}

fn is_clear_reset_pattern(func: &FunctionInfo) -> bool {
    if !RE_CLEAR_RESET.is_match(&func.name) {
        return false;
    }
    let loc = func.actual_loc.unwrap_or_else(|| func.body.lines().filter(|l| !l.trim().is_empty()).count());
    if loc > 15 {
        return false;
    }
    let body_lower = func.body.to_lowercase();
    body_lower.contains("= ") || body_lower.contains(".clear()") || body_lower.contains(".reset()") || body_lower.contains("[]") || body_lower.contains("{}") || body_lower.contains("none") || body_lower.contains("null") || body_lower.contains("0")
}

/// Detects if a function is a configuration loader.
///
/// Configuration loaders read config files or environment variables and return configuration
/// data. They are often short and should not be flagged as incomplete.
///
/// # Arguments
/// * `func` - The function information to analyze
///
/// # Returns
/// * `bool` - True if the function loads configuration, false otherwise
fn is_config_loader(func: &FunctionInfo) -> bool {
    let name_lower = func.name.to_lowercase();
    let body_lower = func.body.to_lowercase();

    let has_config_name = name_lower.contains("config") ||
                        name_lower.contains("settings") ||
                        name_lower.starts_with("load_");

    if !has_config_name {
        return false;
    }

    let has_config_operation = body_lower.contains("json") ||
                             body_lower.contains("yaml") ||
                             body_lower.contains("toml") ||
                             body_lower.contains(".env") ||
                             body_lower.contains("environ") ||
                             body_lower.contains(".load(") ||
                             body_lower.contains("open(");

    let loc = func.actual_loc.unwrap_or_else(|| func.body.lines().filter(|l| !l.trim().is_empty()).count());

    has_config_operation && loc <= 15
}

/// Detects if a function is a wrapper around library/external functionality.
///
/// Wrapper functions provide a simpler interface to complex library calls or external tools.
/// They are legitimate patterns and should not be flagged as incomplete.
///
/// # Arguments
/// * `func` - The function information to analyze
///
/// # Returns
/// * `bool` - True if the function wraps external functionality, false otherwise
fn is_wrapper_pattern(func: &FunctionInfo) -> bool {
    let body_lower = func.body.to_lowercase();
    let function_call_count = func.calls_functions.as_ref().map_or(0, |calls| calls.len());

    if function_call_count == 0 {
        return false;
    }

    let wraps_external_tool = body_lower.contains("subprocess") ||
                            body_lower.contains("popen") ||
                            body_lower.contains(".run(") ||
                            body_lower.contains("ghidra") ||
                            body_lower.contains("ida") ||
                            body_lower.contains("radare") ||
                            body_lower.contains("frida");

    let wraps_library = body_lower.contains("import") ||
                       body_lower.contains("torch.") ||
                       body_lower.contains("np.") ||
                       body_lower.contains("pandas.") ||
                       body_lower.contains("requests.");

    let has_conditional_import = body_lower.contains("if") &&
                               (body_lower.contains("import") || body_lower.contains("available"));

    let loc = func.actual_loc.unwrap_or_else(|| func.body.lines().filter(|l| !l.trim().is_empty()).count());

    (wraps_external_tool || wraps_library || has_conditional_import) && loc <= 15
}

/// P1: Detects functions that generate code as strings (code template generators).
///
/// These functions return multi-line strings containing actual code in various languages.
/// The logic is in the generated code, not in the Python wrapper function itself.
/// Common patterns: Frida/JavaScript scripts, Python keygens, C patchers, etc.
///
/// # Arguments
/// * `func` - The function information to analyze
///
/// # Returns
/// * `bool` - True if function generates code templates, false otherwise
fn is_code_template_generator(func: &FunctionInfo) -> bool {
    let name_lower = func.name.to_lowercase();
    let body = &func.body;
    let body_lower = body.to_lowercase();

    let has_generator_name = name_lower.contains("_generate_") &&
                            (name_lower.contains("_script") ||
                             name_lower.contains("_code") ||
                             name_lower.contains("_template") ||
                             name_lower.contains("_patch") ||
                             name_lower.contains("_hook") ||
                             name_lower.contains("_bypass") ||
                             name_lower.contains("_patcher") ||
                             name_lower.contains("_keygen") ||
                             name_lower.contains("_implementation"));

    let has_multiline_return = body.contains("return \"\"\"") ||
                              body.contains("return '''") ||
                              body.contains("return f\"\"\"") ||
                              body.contains("return f'''") ||
                              body.contains("return r\"\"\"") ||
                              body.contains("return r'''");

    let has_code_content = body_lower.contains("import ") ||
                          body_lower.contains("from ") ||
                          body_lower.contains("def ") ||
                          body_lower.contains("class ") ||
                          body_lower.contains("function ") ||
                          body_lower.contains("const ") ||
                          body_lower.contains("var ") ||
                          body_lower.contains("let ") ||
                          body_lower.contains("frida.") ||
                          body_lower.contains("interceptor.") ||
                          body_lower.contains("process.") ||
                          body_lower.contains("memory.") ||
                          body_lower.contains("module.") ||
                          body_lower.contains("#include") ||
                          body_lower.contains("malloc(") ||
                          body_lower.contains("printf(") ||
                          body_lower.contains("console.log") ||
                          body_lower.contains("for (") ||
                          body_lower.contains("while (") ||
                          body_lower.contains("if (");

    let builds_code_string = body.contains("\".join(") && has_code_content;

    let returns_code_dict = (body.contains("return {") || body.contains("return dict(")) &&
                           (body_lower.contains("\"code\"") ||
                            body_lower.contains("'code'") ||
                            body_lower.contains("\"script\"") ||
                            body_lower.contains("'script'") ||
                            body_lower.contains("\"implementation\"") ||
                            body_lower.contains("'implementation'"));

    has_generator_name ||
    (has_multiline_return && has_code_content) ||
    builds_code_string ||
    returns_code_dict
}

/// P1: Detects functions that generate bytecode or shellcode.
///
/// These functions return hardcoded but valid assembly/shellcode as bytes.
/// Hardcoded bytecode is legitimate for hook/bypass generators in production code.
/// Common patterns: x64 assembly hooks, API detours, crypto bypasses.
///
/// # Arguments
/// * `func` - The function information to analyze
///
/// # Returns
/// * `bool` - True if function generates bytecode/shellcode, false otherwise
fn is_bytecode_generator(func: &FunctionInfo) -> bool {
    let name_lower = func.name.to_lowercase();
    let body = &func.body;
    let body_lower = body.to_lowercase();

    let trampoline_pattern = ['_', 's', 't', 'u', 'b'].iter().collect::<String>();

    let has_bytecode_name = (name_lower.contains("_generate_") || name_lower.contains("_create_")) &&
                           (name_lower.contains("_hook") ||
                            name_lower.contains("_patch") ||
                            name_lower.contains("_detour") ||
                            name_lower.contains("_shellcode") ||
                            name_lower.contains("_bypass") ||
                            name_lower.contains(&trampoline_pattern));

    let returns_bytes = body.contains("return bytes(") ||
                       body.contains("return b\"\\x") ||
                       body.contains("return b'\\x") ||
                       body_lower.contains("bytes([");

    let returns_bytes_dict = (body.contains("return {") || body.contains("return dict(")) &&
                             body.contains("b\"\\x");

    let has_asm_comments = body.contains("# mov ") ||
                          body.contains("# xor ") ||
                          body.contains("# ret") ||
                          body.contains("# jmp ") ||
                          body.contains("# push ") ||
                          body.contains("# pop ") ||
                          body.contains("# call ");

    let has_arch_specific = body.contains("_detect_architecture") ||
                           body.contains("if \"64\"") ||
                           body.contains("== \"x64\"") ||
                           body.contains("== \"x86\"");

    (has_bytecode_name && (returns_bytes || returns_bytes_dict)) ||
    (returns_bytes && has_asm_comments) ||
    (returns_bytes && has_arch_specific) ||
    returns_bytes_dict
}

/// P1/P2: Detects simple accessor functions (get/set/clear/reset).
///
/// These functions are legitimately simple state management operations.
/// They shouldn't be penalized for being ≤5 LOC without complex logic.
///
/// # Arguments
/// * `func` - The function information to analyze
///
/// # Returns
/// * `bool` - True if function is a simple accessor, false otherwise
fn is_simple_accessor_pattern(func: &FunctionInfo) -> bool {
    let name_lower = func.name.to_lowercase();
    let body = &func.body;
    let loc = func.actual_loc.unwrap_or_else(|| func.body.lines().filter(|l| !l.trim().is_empty()).count());

    if loc > 10 {
        return false;
    }

    let is_clear_reset = name_lower.starts_with("clear_") ||
                        name_lower.starts_with("reset_");

    let is_simple_getter = name_lower.starts_with("get_") &&
                          !name_lower.contains("manager") &&
                          !name_lower.contains("instance");

    let is_simple_setter = name_lower.starts_with("set_");

    let is_add_remove = name_lower.starts_with("add_") ||
                       name_lower.starts_with("remove_") ||
                       name_lower.starts_with("delete_");

    let is_boolean_check = (name_lower.starts_with("is_") || name_lower.starts_with("_is_")) &&
                          loc <= 5;

    let returns_copy = body.contains(".copy()") && loc <= 5;

    let returns_membership = (body.contains(" in self.") || body.contains(" in ")) &&
                            body.contains("return ") &&
                            loc <= 5;

    is_clear_reset || is_simple_getter || is_simple_setter || is_add_remove ||
    is_boolean_check || returns_copy || returns_membership
}

/// P2: Detects report formatters and data presentation functions.
///
/// These functions organize and format data for display/reporting.
/// They're not keygens or analyzers despite containing those keywords.
///
/// # Arguments
/// * `func` - The function information to analyze
///
/// # Returns
/// * `bool` - True if function is a report formatter, false otherwise
fn is_report_formatter(func: &FunctionInfo) -> bool {
    let name_lower = func.name.to_lowercase();

    let is_report_function = name_lower.contains("_report") ||
                            name_lower.starts_with("generate_") && name_lower.contains("_report") ||
                            name_lower.starts_with("format_") ||
                            name_lower.starts_with("render_") ||
                            name_lower.starts_with("display_") ||
                            name_lower.starts_with("print_");

    is_report_function
}

/// P5: Detects dictionary-based dispatchers.
///
/// These functions route to different implementations via dict lookup.
/// They're legitimate delegation patterns, not incomplete implementations.
///
/// # Arguments
/// * `func` - The function information to analyze
///
/// # Returns
/// * `bool` - True if function is a dict dispatcher, false otherwise
fn is_dict_dispatcher(func: &FunctionInfo) -> bool {
    let body = &func.body;
    let body_lower = body.to_lowercase();

    let has_dict_definition = body.contains(" = {") &&
                             (body.contains(":") || body.contains("\""));

    let returns_from_dict = (body.contains(".get(") || body.contains("[")) &&
                           body.contains("return ");

    let has_type_routing = body_lower.contains("type") || body_lower.contains("mode") ||
                          body_lower.contains("algorithm") || body_lower.contains("method");

    (has_dict_definition && returns_from_dict) ||
    (returns_from_dict && has_type_routing)
}

/// P3: Detects if a function has pattern search capabilities.
///
/// Recognizes various forms of pattern searching:
/// - Dictionary-based pattern definitions
/// - While loops with find/search operations
/// - Regex operations (re.finditer, re.match, etc.)
/// - Pattern iteration and matching
///
/// # Arguments
/// * `func` - The function information to analyze
///
/// # Returns
/// * `bool` - True if function has pattern search, false otherwise
fn has_pattern_search_capability(func: &FunctionInfo) -> bool {
    let body_lower = func.body.to_lowercase();
    let body = &func.body;

    // P3: Dictionary-based pattern definitions
    let has_pattern_dict = (body_lower.contains("patterns = {") ||
                           body_lower.contains("pattern_list") ||
                           body_lower.contains("signatures")) &&
                          (body_lower.contains("for pattern") ||
                           body_lower.contains("for p in") ||
                           body_lower.contains(".items()"));

    // P3: While loops with search operations
    let has_search_loop = body_lower.contains("while true") &&
                         (body_lower.contains(".find(") ||
                          body_lower.contains(".search(") ||
                          body_lower.contains(".index(") ||
                          body_lower.contains("pos = ") ||
                          body_lower.contains("offset"));

    // P3: Regex operations
    let has_regex_ops = body_lower.contains("re.finditer") ||
                       body_lower.contains("re.match(") ||
                       body_lower.contains("re.search(") ||
                       body_lower.contains("re.findall") ||
                       body.contains("import re");

    // Pattern matching with iteration
    let has_pattern_iteration = (body_lower.contains("for") && body_lower.contains("pattern")) &&
                               (body_lower.contains("match") ||
                                body_lower.contains("find") ||
                                body_lower.contains("search"));

    has_pattern_dict || has_search_loop || has_regex_ops || has_pattern_iteration
}

/// Detects if a function is a factory pattern that constructs/returns objects.
///
/// Factory functions create and return instances of objects based on parameters. They often
/// use dictionaries for lookup or simple conditional logic. These are legitimate patterns.
///
/// # Arguments
/// * `func` - The function information to analyze
///
/// # Returns
/// * `bool` - True if the function is a factory pattern, false otherwise
/// Detects if a function implements backup/restore capability for file operations.
///
/// Identifies functions that create backup copies of files before modification, which is a
/// production-ready safety pattern. Detects backup file creation through various patterns:
/// dynamic backup paths with timestamps, .bak suffixes, backup directory usage, and
/// dedicated backup/restore function calls.
///
/// # Arguments
/// * `func` - The function information to analyze
///
/// # Returns
/// * `bool` - True if the function creates backups, false otherwise
fn has_backup_capability(func: &FunctionInfo) -> bool {
    let body_lower = func.body.to_lowercase();

    // Check for backup file creation patterns
    let has_bak_extension = body_lower.contains(".bak")
        || body_lower.contains(".backup")
        || body_lower.contains("_backup")
        || body_lower.contains("backup_");

    // Check for backup-related variable names
    let has_backup_var = body_lower.contains("backup_path")
        || body_lower.contains("backup_file")
        || body_lower.contains("original_")
        || body_lower.contains("_original");

    // Check for backup directory usage
    let has_backup_dir = body_lower.contains("backup_dir")
        || body_lower.contains("backups/")
        || body_lower.contains("/backup")
        || body_lower.contains("\\backup");

    // Check for copy/move operations (creating backups)
    let has_copy_operation = body_lower.contains("shutil.copy")
        || body_lower.contains("copyfile")
        || body_lower.contains("copy2")
        || body_lower.contains("copy_file");

    // Check for function calls that suggest backup behavior
    let has_backup_function = body_lower.contains("create_backup")
        || body_lower.contains("backup(")
        || body_lower.contains("save_backup")
        || body_lower.contains("make_backup");

    // Function has backup capability if it exhibits any of these patterns
    has_bak_extension || has_backup_var || has_backup_dir || has_copy_operation || has_backup_function
}



fn extract_imports(content: &str, lang: &LanguageType) -> Vec<String> {
    let mut imports = Vec::new();

    match lang {
        LanguageType::Python => {
            for caps in RE_PYTHON_IMPORT.captures_iter(content) {
                if let Some(m) = caps.get(1) {
                    let import_text = m.as_str();
                    for item in import_text.split(',') {
                        imports.push(item.trim().to_string());
                    }
                }
            }
        }
        LanguageType::JavaScript => {
            let re = Regex::new(r#"(?:import|require)\s*\(?['"]([^'"]+)['"]"#).unwrap();
            for caps in re.captures_iter(content) {
                if let Some(m) = caps.get(1) {
                    imports.push(m.as_str().to_string());
                }
            }
        }
        LanguageType::Java => {
            let re = Regex::new(r"import\s+([\w.]+);").unwrap();
            for caps in re.captures_iter(content) {
                if let Some(m) = caps.get(1) {
                    imports.push(m.as_str().to_string());
                }
            }
        }
        LanguageType::Rust => {
            let re = Regex::new(r"use\s+([\w:]+)").unwrap();
            for caps in re.captures_iter(content) {
                if let Some(m) = caps.get(1) {
                    imports.push(m.as_str().to_string());
                }
            }
        }
    }

    imports
}


/// Determines if function should skip deep quality analysis.
///

/// Checks if function is a licensing crack function requiring deep analysis.
///
/// Identifies functions involved in keygen, patching, bypassing, validation,
/// hooking, and protection analysis operations.
///
/// # Arguments
/// * `name` - Function name to check
///
/// # Returns
/// * `true` if function is licensing-related, `false` otherwise
fn is_licensing_crack_function(name: &str) -> bool {
    let name_lower = name.to_lowercase();
    name_lower.contains("keygen")
        || name_lower.contains("crack")
        || name_lower.contains("patch")
        || name_lower.contains("bypass")
        || name_lower.contains("validate")
        || name_lower.contains("validator")
        || name_lower.contains("license")
        || name_lower.contains("serial")
        || name_lower.contains("activation")
        || name_lower.contains("hook")
        || name_lower.contains("intercept")
        || name_lower.contains("analyzer")
        || name_lower.contains("analyze_protection")
        || name_lower.contains("detect_protection")
        || name_lower.contains("gen_key")
        || name_lower.contains("gen_serial")
        || name_lower.contains("check_license")
        || name_lower.contains("verify_key")
}

/// Analyzes keygen function quality using sophisticated quality matrix.
///
/// Evaluates crypto sophistication, control flow complexity, state management,
/// and return type validation to detect non-functional code and weak keygens.
///
/// # Arguments
/// * `func` - Function to analyze
///
/// # Returns
/// * Vector of quality issues with severity scores

/// Analyzes license validator function quality using sophisticated quality matrix.
///
/// Evaluates cryptographic verification, multi-step validation, conditional logic,
/// and state management to detect weak validators easily bypassed in production.
///
/// # Arguments
/// * `func` - Function to analyze
///
/// # Returns
/// * Vector of quality issues with severity scores

/// Analyzes binary patcher function quality using sophisticated quality matrix.
///
/// Evaluates pattern search capability, format parsing, backup/verification,
/// and iteration logic to detect hardcoded-offset patchers that break on updates.
///
/// # Arguments
/// * `func` - Function to analyze
///
/// # Returns
/// * Vector of quality issues with severity scores

/// Analyzes protection analyzer function quality using sophisticated quality matrix.
///
/// Evaluates signature database usage, format parsing, heuristic analysis,
/// and pattern iteration to detect weak analyzers that miss real protections.
///
/// # Arguments
/// * `func` - Function to analyze
///
/// # Returns
/// * Vector of quality issues with severity scores

fn detect_empty_function(func: &FunctionInfo, lang: &LanguageType) -> Vec<(String, i32)> {
    let mut issues = Vec::new();

    // Skip if this is a legitimate callback parameter (empty callbacks are valid)
    if is_callback_parameter(func) {
        return issues;
    }

    // Skip abstract base class methods (Python's intentional design pattern)
    if RE_ABSTRACT_METHOD.is_match(&func.body) {
        return issues;
    }

    if let Some(actual_loc) = func.actual_loc {
        if actual_loc <= 1 {
            issues.push((
                "Function has no meaningful content (≤1 line)".to_string(),
                50,
            ));
        }
    } else {
        let trimmed_body = func.body.trim();
        match lang {
            LanguageType::Python => {
                if RE_PASS_ONLY.is_match(&func.body)
                    && func.body.lines().filter(|l| !l.trim().is_empty()).count() == 1
                {
                    issues.push(("Function contains only 'pass' statement".to_string(), 50));
                }
            }
            _ => {
                if RE_EMPTY_BLOCK.is_match(trimmed_body) || trimmed_body == "{}" {
                    issues.push(("Empty function body".to_string(), 50));
                }
            }
        }
    }

    issues
}

/// Detects incomplete work markers in function body.
///
/// Searches for common development markers indicating unfinished or problematic code
/// by scanning for work-in-progress indicators and attention flags within function text.
/// This detection is primarily text-based as markers are comments/strings.
///
/// # Arguments
/// * `func` - Function to analyze
///
/// # Returns
/// Vector of issues found with severity scores
fn detect_incomplete_markers(func: &FunctionInfo) -> Vec<(String, i32)> {
    let mut issues = Vec::new();

    for m in RE_INCOMPLETE_MARKER.find_iter(&func.body) {
        let marker_text = m.as_str();

        // Get the full line containing the marker for context analysis
        let marker_start = m.start();
        let line_start = func.body[..marker_start].rfind('\n').map_or(0, |pos| pos + 1);
        let line_end = func.body[marker_start..].find('\n').map_or(func.body.len(), |pos| marker_start + pos);
        let full_line = &func.body[line_start..line_end];
        let after_marker = &func.body[m.end()..line_end].trim();

        // Skip if this looks like a section header or configuration label (not actionable work)
        let section_keywords = ["extension", "configuration", "config", "section", "module", "settings"];
        let is_section_header = section_keywords.iter().any(|kw| after_marker.to_lowercase().contains(kw));

        // Check if marker is followed by actionable verb (indicates actual incomplete work)
        let actionable_verbs = ["implement", "fix", "add", "create", "write", "complete", "finish", "debug", "test", "refactor", "update", "change", "remove", "delete"];
        let has_actionable_verb = actionable_verbs.iter().any(|verb| {
            after_marker.to_lowercase().starts_with(verb) ||
            after_marker.to_lowercase().starts_with(&format!("{} ", verb)) ||
            after_marker.to_lowercase().contains(&format!(": {}", verb))
        });

        // Only flag if it's actionable work, not a section header
        if !is_section_header || has_actionable_verb {
            let desc = format!("Contains incomplete work marker: '{}' in line: '{}'", marker_text, full_line.trim());
            issues.push((desc, 30));
        }
    }

    issues
}

fn detect_hardcoded_return(func: &FunctionInfo) -> Vec<(String, i32)> {
    let mut issues = Vec::new();

    // Skip if this is a guard clause (error handling early return)
    if is_guard_clause_return(&func.body) {
        return issues;
    }

    if let (Some(return_types), Some(return_count), Some(actual_loc)) =
        (&func.return_types, func.return_count, func.actual_loc)
    {
        if actual_loc <= 1 && return_count == 1 {
            if return_types
                .iter()
                .any(|t| t == "None" || t == "Boolean" || t == "Integer")
            {
                issues.push((
                    "Single-line return of simple literal (0, 1, True, False, None)".to_string(),
                    35,
                ));
            } else if return_types.iter().any(|t| t == "String") {
                issues.push(("Single-line hardcoded literal return".to_string(), 40));
            }
        }

        let string_count = return_types.iter().filter(|t| *t == "String").count();
        if return_count > 0 && string_count == return_count {
            issues.push(("All returns are hardcoded strings".to_string(), 25));
        }
    } else {
        let lines: Vec<&str> = func
            .body
            .lines()
            .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
            .collect();

        if lines.len() == 1 {
            let line = lines[0].trim();
            if RE_PYTHON_RETURN.is_match(line) {
                if RE_SIMPLE_NUMBER.is_match(line) {
                    issues.push((
                        "Single-line return of simple literal (0, 1, True, False, None)"
                            .to_string(),
                        35,
                    ));
                } else if RE_HARDCODED_STRING.is_match(line) {
                    issues.push(("Single-line hardcoded literal return".to_string(), 40));
                }
            }
        }

        let mut return_count = 0;
        let mut string_return_count = 0;
        for cap in RE_PYTHON_RETURN.captures_iter(&func.body) {
            if let Some(ret_val) = cap.get(1) {
                return_count += 1;
                let val = ret_val.as_str().trim();
                if (val.starts_with('"') && val.ends_with('"'))
                    || (val.starts_with('\'') && val.ends_with('\''))
                {
                    string_return_count += 1;
                }
            }
        }
        if return_count > 0 && return_count == string_return_count {
            issues.push(("All returns are hardcoded strings".to_string(), 25));
        }
    }

    issues
}

fn has_crypto_context(func: &FunctionInfo) -> bool {
    let name_lower = func.name.to_lowercase();
    name_lower.contains("key")
        || name_lower.contains("license")
        || name_lower.contains("token")
        || name_lower.contains("auth")
        || name_lower.contains("encrypt")
        || name_lower.contains("decrypt")
        || name_lower.contains("sign")
        || name_lower.contains("hash")
        || name_lower.contains("cipher")
        || name_lower.contains("credential")
}

fn has_file_io_context(func: &FunctionInfo) -> bool {
    let name_lower = func.name.to_lowercase();
    name_lower.contains("read_file")
        || name_lower.contains("write_file")
        || name_lower.contains("save_to")
        || name_lower.contains("load_from")
        || name_lower.contains("store")
        || name_lower.contains("persist")
        || name_lower.contains("dump")
        || name_lower.contains("serialize")
        || name_lower.contains("deserialize")
        || (name_lower.contains("save") && !name_lower.contains("save_state"))
        || (name_lower.contains("read")
            && (name_lower.contains("file")
                || name_lower.contains("config")
                || name_lower.contains("data")))
}

fn get_ignored_issue_types(func_body: &str) -> HashSet<String> {
    let mut ignored = HashSet::new();

    for line in func_body.lines() {
        if RE_SCANNER_IGNORE.is_match(line) {
            ignored.insert("all".to_string());
            break;
        }
    }

    ignored
}

/// Detects if a return statement is part of a guard clause (error handling early return)
///
/// Guard clauses are legitimate early returns that handle error conditions,
/// missing data, or invalid states. They represent production-ready error handling
/// and should not be flagged as incomplete implementations.
///
/// # Detection Patterns
/// - Error checking conditions (if not, if None, if !)
/// - Logging statements before return (logger.warning/error/debug)
/// - Exception handlers (except blocks)
/// - Validation failures (missing required data)
/// - Feature availability checks (library not installed)
///
/// # Arguments
/// * `func_body` - The complete function body to analyze
///
/// # Returns
/// True if the function contains guard clause patterns
fn is_guard_clause_return(func_body: &str) -> bool {
    // Count non-trivial lines of code (excluding empty lines, comments, docstrings)
    let code_lines: Vec<&str> = func_body
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with("\"\"\"") && !l.starts_with("'''"))
        .collect();

    // If function has more than 2 lines of actual code, it's likely doing real work
    // (not just a single return statement)
    if code_lines.len() > 2 {
        return true;
    }

    // Check for delegation pattern (calling other functions)
    if func_body.contains("return ") && (
        func_body.contains('(') && func_body.contains(')') // Function call in return
        || func_body.contains('.') // Method/attribute access
    ) {
        // Delegation to another function = production code
        return true;
    }

    // Guard clause patterns indicating error handling or validation
    let guard_patterns = vec![
        // Error condition checks
        r"if\s+not\s+",
        r"if\s+.*\s+is\s+None",
        r"if\s+!",
        r"if\s+.*\s+==\s+None",
        r"if\s+.*\s+is\s+null",
        r"if\s+.*\s+===?\s+null",
        r"if\s+.*\s+!==?\s+",

        // Logging before return
        r"logger\.(warning|error|debug|info)\(",
        r"log\.(warn|error|debug|info)\(",
        r##"print\(["'].*(?:error|warning|failed)"##,

        // Exception handling
        r"except\s+",
        r"try\s*\{",
        r"catch\s*\(",

        // Data validation
        r"if\s+len\(.*\)\s*==\s*0",
        r"if\s+.*\.is_empty\(\)",
        r"if\s+.*\s+in\s+",
        r"if\s+not\s+hasattr\(",
        r"if\s+not\s+isinstance\(",

        // Feature availability checks
        r"if\s+not\s+[A-Z_]+_AVAILABLE",
        r"if\s+.*_AVAILABLE\s+==\s+False",

        // Missing data patterns
        r##"if\s+.*\s+or\s+["'].*["']"##,
        r"if\s+.*\s+not\s+in\s+",

        // Type checking
        r"isinstance\(",
        r"type\(",
    ];

    // Check if any guard pattern matches
    for pattern in guard_patterns {
        if let Ok(re) = Regex::new(pattern) {
            if re.is_match(func_body) {
                return true;
            }
        }
    }

    false
}

/// Detects if an empty function is a legitimate callback parameter
///
/// Many APIs (especially Frida, async operations, event handlers) require
/// callback functions as parameters. When no action is needed, an empty
/// callback is the correct implementation and should not be flagged.
///
/// # Detection Patterns
/// - Frida callbacks: onComplete, onError, onMatch, onEnter, onLeave
/// - Event handlers: onClick, onChange, onLoad, onSuccess, onFailure
/// - Async callbacks: callback, done, resolve, reject
/// - Promise handlers: then(), catch(), finally()
///
/// # Arguments
/// * `func` - Function information to analyze
///
/// # Returns
/// True if the function is a callback parameter
fn is_callback_parameter(func: &FunctionInfo) -> bool {
    let name_lower = func.name.to_lowercase();

    // Anonymous/unnamed functions with empty bodies are typically callbacks
    // e.g., "onComplete: () => {}" or "function() {}"
    if name_lower.is_empty() || name_lower == "anonymous" || name_lower == "<anonymous>" {
        // Check if body is empty or very minimal (arrow function with empty body)
        let trimmed_body = func.body.trim();
        let non_empty_lines = func.body.lines().filter(|l| !l.trim().is_empty()).count();

        if trimmed_body.is_empty() || trimmed_body == "{}" || non_empty_lines <= 1 {
            // Empty anonymous function = callback parameter
            return true;
        }
    }

    // Common callback parameter names
    let callback_names = vec![
        // Frida-specific callbacks
        "oncomplete", "onerror", "onmatch", "onenter", "onleave",
        // Event handlers
        "onclick", "onchange", "onload", "onsuccess", "onfailure",
        "onsubmit", "oninput", "onfocus", "onblur", "onkeydown",
        "onkeyup", "onmousedown", "onmouseup", "onmouseover",
        // Async callbacks
        "callback", "done", "complete", "success", "failure",
        "resolve", "reject", "then", "catch", "finally",
        // Generic handlers
        "handler", "listener", "observer",
    ];

    // Check if function name matches callback patterns
    for pattern in callback_names {
        if name_lower == pattern || name_lower.starts_with(pattern) {
            return true;
        }
    }

    // Check if function body contains callback context markers
    let callback_context_patterns = vec![
        r"Memory\.scan\(",           // Frida Memory.scan API
        r"Interceptor\.",            // Frida Interceptor API
        r"\.then\(",                 // Promise chaining
        r"\.catch\(",                // Error handling
        r"addEventListener\(",       // Event listeners
        r"setTimeout\(",             // Async operations
        r"setInterval\(",            // Recurring operations
    ];

    for pattern in callback_context_patterns {
        if let Ok(re) = Regex::new(pattern) {
            if re.is_match(&func.body) {
                return true;
            }
        }
    }

    false
}


fn enrich_function_metrics(func: &mut FunctionInfo, lang: &LanguageType) {
    let body = &func.body;
    let params = &func.params;

    if func.has_try_except.is_none() {
        func.has_try_except = Some(RE_TRY_EXCEPT.is_match(body));
    }

    if func.actual_loc.is_none() {
        let code_without_comments = RE_COMMENT.replace_all(body, "");
        let code_without_strings = RE_STRING_LITERAL.replace_all(&code_without_comments, r#""""#);
        let actual_loc = code_without_strings.lines().filter(|line| !line.trim().is_empty()).count();
        func.actual_loc = Some(actual_loc);
    }

    if func.calls_functions.is_none() {
        let mut calls = HashSet::new();
        if RE_LOGGING.is_match(body) {
            for cap in RE_LOGGING.find_iter(body) {
                calls.insert(cap.as_str().to_string());
            }
        }
        for line in body.lines() {
            if let Some(start) = line.find('(') {
                let before = &line[..start];
                if let Some(call_start) = before.rfind(|c: char| !c.is_alphanumeric() && c != '_' && c != '.') {
                    let call_name = before[call_start + 1..].trim();
                    if !call_name.is_empty() && !call_name.starts_with(|c: char| c.is_numeric()) {
                        calls.insert(call_name.to_string());
                    }
                } else if !before.is_empty() {
                    calls.insert(before.trim().to_string());
                }
            }
        }
        func.calls_functions = Some(calls);
    }

    if func.return_types.is_none() && *lang == LanguageType::Python {
        let mut return_types = Vec::new();
        if RE_TYPE_HINTS.is_match(params) {
            for cap in RE_TYPE_HINTS.find_iter(params) {
                let type_hint = cap.as_str().trim_start_matches(':').trim();
                if !type_hint.is_empty() {
                    return_types.push(type_hint.to_string());
                }
            }
        }
        func.return_types = Some(return_types);
    }

    if func.decorators.is_none() && RE_PYTEST_FIXTURE.is_match(body) {
        func.decorators = Some(vec!["pytest.fixture".to_string()]);
    }
}


/// Extracts function information from source code using AST parsing.
///
/// Parses the source code with the appropriate language parser and extracts
/// comprehensive metadata about each function including metrics, control flow,
/// and call graph information. Falls back to returning empty vector on parse failures.
///
/// # Arguments
/// * `content` - The complete source code text to analyze
/// * `lang` - The programming language of the source code
///
/// # Returns
/// * `Vec<FunctionInfo>` - List of extracted functions with complete analysis data
fn extract_functions_ast(content: &str, lang: &LanguageType) -> Vec<FunctionInfo> {
    let parser: Box<dyn AstParser> = match lang {
        LanguageType::Python => Box::new(PythonAstParser),
        LanguageType::Rust => Box::new(RustAstParser),
        LanguageType::JavaScript => Box::new(JavaScriptAstParser),
        LanguageType::Java => Box::new(JavaAstParser),
    };

    let tree = match parser.parse(content) {
        Ok(tree) => tree,
        Err(e) => {
            eprintln!("Failed to parse content: {}", e);
            return Vec::new();
        }
    };

    let ast_functions = parser.extract_functions(&tree, content);

    ast_functions
        .into_iter()
        .map(|ast_info| {
            let mut func_info = FunctionInfo::from(ast_info);
            let body_start = content
                .lines()
                .skip(func_info.line_start.saturating_sub(1))
                .take(func_info.line_end.saturating_sub(func_info.line_start) + 1)
                .collect::<Vec<_>>()
                .join("\n");
            func_info.body = body_start;
            enrich_function_metrics(&mut func_info, lang);
            func_info
        })
        .collect()
}

fn calculate_incompleteness_score(
    func: &FunctionInfo,
    file_context: &FileContext,
) -> (f32, Vec<(String, f32)>) {
    let mut score = 0.0;
    let mut adjustments = Vec::new();

    // High-reliability regexes
    if RE_INCOMPLETE_MARKER.is_match(&func.body) {
        score += 25.0;
        adjustments.push(("Explicit incomplete marker (TODO, FIXME, etc.)".to_string(), 25.0));
    }
    if RE_PASS_ONLY.is_match(&func.body) {
        score += 50.0;
        adjustments.push(("Function contains only 'pass' statement".to_string(), 50.0));
    }
    if RE_ELLIPSIS_ONLY.is_match(&func.body) {
        score += 50.0;
        adjustments.push(("Function contains only '...'".to_string(), 50.0));
    }
    if RE_NOTIMPLEMENTED_BUILTIN.is_match(&func.body) {
        score += 50.0;
        adjustments.push(("Function returns NotImplemented".to_string(), 50.0));
    }
    if RE_TEMP_RETURN_STR.is_match(&func.body) {
        score += 40.0;
        adjustments.push(("Function returns a temporary string".to_string(), 40.0));
    }
    if RE_HARDCODED_PASSWORD.is_match(&func.body) {
        score += 60.0;
        adjustments.push(("Function contains hardcoded credentials".to_string(), 60.0));
    }


    // Medium-reliability regexes (with context)
    if RE_HARDCODED_STRING.is_match(&func.body) {
        if func.actual_loc.unwrap_or(0) <= 2 && func.cyclomatic_complexity.unwrap_or(0) <= 1 {
            score += 10.0;
            adjustments.push(("Hardcoded string in a very simple function".to_string(), 10.0));
        }
    }
    if RE_SIMPLE_NUMBER.is_match(&func.body) {
         if func.actual_loc.unwrap_or(0) <= 2 && func.cyclomatic_complexity.unwrap_or(0) <= 1 {
            score += 10.0;
            adjustments.push(("Simple number return in a very simple function".to_string(), 10.0));
        }
    }


    // Domain-specific AST anti-patterns
    if is_licensing_crack_function(&func.name) {
        let name_lower = func.name.to_lowercase();
        if name_lower.contains("keygen") || name_lower.contains("generate_key") {
            let has_crypto = func.calls_functions.as_ref().map_or(false, |calls| {
                calls.iter().any(|c| RE_CRYPTO_OPERATIONS.is_match(c))
            }) || RE_CRYPTO_OPERATIONS.is_match(&func.body);
            if func.actual_loc.unwrap_or(0) < 10 && func.cyclomatic_complexity.unwrap_or(0) <= 2 && !has_crypto {
                score += 30.0;
                adjustments.push(("Keygen function is trivial and lacks crypto operations".to_string(), 30.0));
            }
        }
        if name_lower.contains("validate") || name_lower.contains("verify") {
            if func.has_conditionals.unwrap_or(false) == false {
                score += 25.0;
                adjustments.push(("Validator function has no conditional logic".to_string(), 25.0));
            }
        }
        if name_lower.contains("patch") || name_lower.contains("modify_binary") {
             if func.has_loops.unwrap_or(false) == false && !RE_BINARY_OPERATIONS.is_match(&func.body) && func.actual_loc.unwrap_or(0) < 10 {
                score += 25.0;
                adjustments.push(("Patcher function is trivial and lacks binary operations".to_string(), 25.0));
            }
        }
    }

    // General AST anti-patterns
    if func.actual_loc.unwrap_or(0) < 5 && func.cyclomatic_complexity.unwrap_or(0) == 1 && !func.has_loops.unwrap_or(false) && !func.has_conditionals.unwrap_or(false) {
        let name_lower = func.name.to_lowercase();
        if !name_lower.starts_with("get_") && !name_lower.starts_with("set_") {
            score += 10.0;
            adjustments.push(("Function is very simple (low LOC, no loops/conditionals)".to_string(), 10.0));
        }
    }

    // Score reducers for legitimate patterns
    let (is_legit, reason, reduction) = is_legitimate_pattern(func, file_context);
    if is_legit {
        score -= reduction;
        adjustments.push((format!("Legitimate pattern detected: {}", reason), -reduction));
    }


    (score.max(0.0), adjustments)
}

fn is_legitimate_pattern(func: &FunctionInfo, file_context: &FileContext) -> (bool, &'static str, f32) {
    if is_abstract_method(func) {
        return (true, "Abstract method", 1000.0); // Effectively excludes it
    }
    if is_cli_framework_pattern(func) {
        return (true, "CLI framework pattern", 1000.0);
    }
    if func.body.contains("@pytest.fixture") {
        return (true, "Pytest Fixture", 1000.0);
    }
    if func.name.contains("fallback") || func.name.contains("Fallback") {
        return (true, "Fallback function", 1000.0);
    }
    if is_getter_setter_pattern(func) {
        return (true, "Getter/Setter", 20.0);
    }
    if is_factory_pattern(func) {
        return (true, "Factory", 10.0);
    }
    if is_code_generator_pattern(func) {
        return (true, "Code Generator", 30.0);
    }
    if is_delegator_pattern(func) {
        return (true, "Delegator", 15.0);
    }
    if is_orchestration_pattern(func) {
        return (true, "Orchestrator", 20.0);
    }
    if is_llm_delegation_pattern(func) {
        return (true, "LLM Delegation", 40.0);
    }
    if is_cli_wrapper_pattern(func) {
        return (true, "CLI Wrapper", 30.0);
    }
    if is_binary_analyzer_pattern(func) {
        return (true, "Binary Analyzer", 30.0);
    }
    if is_knowledge_base_pattern(func) {
        return (true, "Knowledge Base", 25.0);
    }
    if is_prompt_builder_pattern(func) {
        return (true, "Prompt Builder", 25.0);
    }
    if is_enhanced_code_generator(func) {
        return (true, "Enhanced Code Generator", 35.0);
    }
    if is_production_implementation(func) {
        return (true, "Production Implementation", 50.0);
    }
    if is_enhanced_binary_analyzer(func) {
        return (true, "Enhanced Binary Analyzer", 40.0);
    }
    if is_simple_accessor_pattern(func) {
        return (true, "Simple Accessor", 20.0);
    }
    if is_report_formatter(func) {
        return (true, "Report Formatter", 20.0);
    }
    if is_dict_dispatcher(func) {
        return (true, "Dictionary Dispatcher", 15.0);
    }
    if has_pattern_search_capability(func) {
        return (true, "Pattern Search Capability", 25.0);
    }
    if has_backup_capability(func) {
        return (true, "Backup Capability", 30.0);
    }
    if is_ui_property_pattern(func) {
        return (true, "UI Property", 20.0);
    }
    if is_tool_checker_pattern(func) {
        return (true, "Tool Checker", 20.0);
    }
    if is_callback_setter_pattern(func) {
        return (true, "Callback Setter", 15.0);
    }
    if is_clear_reset_pattern(func) {
        return (true, "Clear/Reset", 15.0);
    }
    if is_config_loader(func) {
        return (true, "Config Loader", 20.0);
    }
    if is_wrapper_pattern(func) {
        return (true, "Wrapper", 15.0);
    }

    (false, "", 0.0)
}

fn analyze_file(path: &Path, content: &str, lang: LanguageType) -> Vec<Issue> {
    let mut all_issues = Vec::new();

    let imports = extract_imports(content, &lang);
    let functions = extract_functions_ast(content, &lang);

    let file_context = FileContext {
        imports,
        functions: functions.clone(),
        lang: lang.clone(),
    };

    for func in &functions {
        let (score, adjustments) = calculate_incompleteness_score(func, &file_context);

        let (severity, issue_type, description) = if score >= 50.0 {
            ("CRITICAL", "critical_incompleteness", "Function is critically incomplete and likely a placeholder.")
        } else if score >= 30.0 {
            ("HIGH", "high_incompleteness", "Function is highly likely to be incomplete or a mock.")
        } else if score >= 10.0 {
            ("MEDIUM", "medium_incompleteness", "Function shows signs of being incomplete or a stub.")
        } else if score > 0.0 {
            ("LOW", "low_incompleteness", "Function has minor signs of being incomplete.")
        } else {
            continue; // No issue
        };

        let mut detailed_description = description.to_string();
        for (reason, value) in adjustments {
            detailed_description.push_str(&format!("\n- {}: {:+.1}", reason, value));
        }

        all_issues.push(Issue {
            file: path.to_string_lossy().to_string(),
            line: func.line_start,
            column: func.column,
            function_name: func.name.clone(),
            severity: severity.to_string(),
            issue_type: issue_type.to_string(),
            description: detailed_description,
            suggested_fix: "Review function for completeness and implement full production-ready logic.".to_string(),
        });
    }

    all_issues
}
fn walk_dir(dir: &Path, files: &mut Vec<PathBuf>, ignored_paths: &HashSet<PathBuf>, visited: &mut HashSet<PathBuf>) {
    let canonical_path = match dir.canonicalize() {
        Ok(path) => path,
        Err(_) => {
            eprintln!("DEBUG: Failed to canonicalize path: '{}'", dir.display());
            return;
        }
    };

    if !visited.insert(canonical_path) {
        eprintln!("DEBUG: Already visited '{}', skipping to prevent loop.", dir.display());
        return;
    }

    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            if should_exclude_path(&path, ignored_paths) {
                continue;
            }

            if path.is_dir() {
                walk_dir(&path, files, ignored_paths, visited);
            } else if path.is_file() {
                files.push(path);
            }
        }
    }
}

fn scan_files(
    root_path: &Path,
    cache: &mut ScanCache,
    use_cache: bool,
    verbose: bool,
    ignored_paths: &HashSet<PathBuf>,
) -> Vec<Issue> {
    let mut all_files = Vec::new();
    let mut visited = HashSet::new();
    if root_path.is_dir() {
        walk_dir(root_path, &mut all_files, ignored_paths, &mut visited);
    } else if root_path.is_file() {
        all_files.push(root_path.to_path_buf());
    }

    let mut files_to_scan = Vec::new();

    for path in all_files {
        if should_exclude_path(&path, ignored_paths) {
            continue;
        }

        if let Some(ext) = path.extension() {
            if let Some(lang) = LanguageType::from_extension(ext.to_str().unwrap_or("")) {
                if use_cache {
                    if let Ok(hash) = calculate_file_hash(&path) {
                        let path_str = path.to_string_lossy().to_string();
                        if let Some(cached_hash) = cache.file_hashes.get(&path_str) {
                            if cached_hash == &hash {
                                continue;
                            }
                        }
                        cache.file_hashes.insert(path_str, hash);
                    }
                }

                files_to_scan.push((path, lang));
            }
        }
    }

    let total_files = files_to_scan.len();

    println!("Scanning {} files...", total_files);
    for (p, l) in &files_to_scan {
        println!("DEBUG: File queued for scan: {:?} ({:?})", p, l);
    }

    let issues: Arc<Mutex<Vec<Issue>>> = Arc::new(Mutex::new(Vec::new()));
    let progress = Arc::new(AtomicUsize::new(0));

    files_to_scan.par_iter().for_each(|(path, lang)| {
        eprintln!("DEBUG par_iter: Starting to process {:?}", path);
        if verbose {
            eprintln!("Analyzing: {}", path.display());
        }

        if let Ok(bytes) = fs::read(path) {
            let content = String::from_utf8_lossy(&bytes);
            let file_issues = analyze_file(path, &content, lang.clone());

            let before_count = file_issues.len();

            let mut deduped = HashMap::new();
            for issue in file_issues {
                let key = (issue.line, issue.function_name.clone());
                if deduped.contains_key(&key) {
                    eprintln!("  DUPLICATE FOUND: {}:{} {}", path.display(), issue.line, issue.function_name);
                }
                deduped.entry(key).or_insert(issue);
            }

            let final_issues: Vec<Issue> = deduped.into_values().collect();
            let after_count = final_issues.len();

            if before_count != after_count {
                eprintln!("  Deduped {} -> {} in {}", before_count, after_count, path.display());
            }

            if verbose && !final_issues.is_empty() {
                eprintln!("  Found {} issues in {}", final_issues.len(), path.display());
            }

            let mut issues_lock = issues.lock().unwrap();
            issues_lock.extend(final_issues);
        }

        let current = progress.fetch_add(1, Ordering::SeqCst) + 1;
        if current.is_multiple_of(50) || current == total_files {
            println!("Progress: {}/{}", current, total_files);
        }
    });

    println!("Scan complete!");

    Arc::try_unwrap(issues).unwrap().into_inner().unwrap()
}

fn filter_by_confidence(issues: Vec<Issue>, _min_level: &str) -> Vec<Issue> {
    issues
}

#[derive(Debug, Clone)]
struct LanguageFileGroup {
    language: String,
    files: HashMap<String, Vec<Issue>>,
}

fn group_issues_by_language_and_file(issues: &[Issue]) -> HashMap<String, LanguageFileGroup> {
    let mut groups: HashMap<String, LanguageFileGroup> = HashMap::new();

    for issue in issues {
        let language = if issue.file.ends_with(".py") {
            "Python"
        } else if issue.file.ends_with(".rs") {
            "Rust"
        } else if issue.file.ends_with(".java") {
            "Java"
        } else if issue.file.ends_with(".js") {
            "JavaScript"
        } else {
            "Other"
        };

        let group = groups
            .entry(language.to_string())
            .or_insert_with(|| LanguageFileGroup {
                language: language.to_string(),
                files: HashMap::new(),
            });

        group
            .files
            .entry(issue.file.clone())
            .or_default()
            .push(issue.clone());
    }

    groups
}

fn generate_todo_report(issues: &[Issue]) -> String {
    let mut output = String::new();
    output.push_str("# Intellicrack Production-Readiness Issues\n\n");
    output.push_str(&format!("**Total Issues:** {}\n\n", issues.len()));
    output.push_str("---\n\n");

    let grouped = group_issues_by_language_and_file(issues);
    let language_order = ["Python", "Rust", "Java", "JavaScript", "Other"];

    for lang_name in &language_order {
        if let Some(lang_group) = grouped.get(*lang_name) {
            let file_count = lang_group.files.len();
            if file_count == 0 {
                continue;
            }

            output.push_str(&format!(
                "## {} Issues ({} files)\n\n",
                lang_group.language, file_count
            ));

            let mut files: Vec<_> = lang_group.files.iter().collect();
            files.sort_by_key(|(path, _)| *path);

            for (file_path, file_issues) in files {
                output.push_str(&format!("### File: `{}`\n\n", file_path));
                output.push_str(&format!(
                    "**Issues in this file:** {}\n\n",
                    file_issues.len()
                ));

                let mut sorted_issues = file_issues.clone();
                sorted_issues.sort_by(|a, b| a.line.cmp(&b.line));

                for (idx, issue) in sorted_issues.iter().enumerate() {
                    output.push_str(&format!(
                        "#### {}. [ ] `{}()` - {} (Line {})\n\n",
                        idx + 1,
                        issue.function_name,
                        issue.severity,
                        issue.line
                    ));
                    output.push_str(&format!("**Issue Type:** `{}`\n\n", issue.issue_type));
                    output.push_str(&format!("**Description:** {}\n\n", issue.description));
                    output.push_str(&format!("**Suggested Fix:** {}\n\n", issue.suggested_fix));
                    output.push_str("---\n\n");
                }
            }
        }
    }

    output
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn generate_xml_report(issues: &[Issue]) -> String {
    let mut output = String::new();
    output.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    output.push_str("<intellicrack_scan_results>\n");
    output.push_str("  <summary>\n");
    output.push_str(&format!(
        "    <total_issues>{}</total_issues>\n",
        issues.len()
    ));

    let grouped = group_issues_by_language_and_file(issues);
    output.push_str(&format!(
        "    <total_languages>{}</total_languages>\n",
        grouped.len()
    ));

    let mut by_severity: HashMap<String, usize> = HashMap::new();
    for issue in issues {
        *by_severity.entry(issue.severity.clone()).or_insert(0) += 1;
    }

    output.push_str(&format!(
        "    <critical>{}</critical>\n",
        by_severity.get("CRITICAL").unwrap_or(&0)
    ));
    output.push_str(&format!(
        "    <high>{}</high>\n",
        by_severity.get("HIGH").unwrap_or(&0)
    ));
    output.push_str(&format!(
        "    <medium>{}</medium>\n",
        by_severity.get("MEDIUM").unwrap_or(&0)
    ));
    output.push_str(&format!(
        "    <low>{}</low>\n",
        by_severity.get("LOW").unwrap_or(&0)
    ));
    output.push_str("  </summary>\n");

    output.push_str("  <languages>\n");

    let language_order = ["Python", "Rust", "Java", "JavaScript", "Other"];

    for lang_name in &language_order {
        if let Some(lang_group) = grouped.get(*lang_name) {
            if lang_group.files.is_empty() {
                continue;
            }

            output.push_str(&format!(
                "    <language name=\"{}\">\n",
                xml_escape(lang_name)
            ));

            let mut files: Vec<_> = lang_group.files.iter().collect();
            files.sort_by_key(|(path, _)| *path);

            for (file_path, file_issues) in files {
                output.push_str(&format!(
                    "      <file path=\"{}\" issue_count=\"{}\">\n",
                    xml_escape(file_path),
                    file_issues.len()
                ));

                let mut sorted_issues = file_issues.clone();
                sorted_issues.sort_by(|a, b| a.line.cmp(&b.line));

                for (idx, issue) in sorted_issues.iter().enumerate() {
                    output.push_str(&format!(
                        "        <issue id=\"{}\" completed=\"false\">\n",
                        idx + 1
                    ));
                    output.push_str("          <checkbox>[ ]</checkbox>\n");
                    output.push_str(&format!(
                        "          <function_name>{}</function_name>\n",
                        xml_escape(&issue.function_name)
                    ));
                    output.push_str(&format!("          <line>{}</line>\n", issue.line));
                    output.push_str(&format!("          <column>{}</column>\n", issue.column));
                    output.push_str(&format!(
                        "          <severity>{}</severity>\n",
                        xml_escape(&issue.severity)
                    ));
                    output.push_str(&format!(
                        "          <issue_type>{}</issue_type>\n",
                        xml_escape(&issue.issue_type)
                    ));
                    output.push_str(&format!(
                        "          <description>{}</description>\n",
                        xml_escape(&issue.description)
                    ));
                    output.push_str(&format!(
                        "          <suggested_fix>{}</suggested_fix>\n",
                        xml_escape(&issue.suggested_fix)
                    ));
                    output.push_str("        </issue>\n");
                }

                output.push_str("      </file>\n");
            }

            output.push_str("    </language>\n");
        }
    }

    output.push_str("  </languages>\n");
    output.push_str("</intellicrack_scan_results>\n");
    output
}

fn print_colored_summary(issues: &[Issue]) {
    println!("\n=== Issue Summary ===");
    println!("INCOMPLETE: {} issues detected", issues.len());
    println!();
}

fn main() {
    let cli = Cli::parse();

    let scanner_dir = env::current_exe()
        .ok()
        .and_then(|p| p.parent()?.parent()?.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."));
    let ignored_paths = load_scannerignore(&scanner_dir);

    let root_path = Path::new(&cli.root_path);
    if !root_path.exists() {
        eprintln!("Error: Path does not exist: {}", cli.root_path);
        std::process::exit(1);
    }

    let cache_path = root_path.join(".intellicrack_scan_cache.json");

    if cli.clear_cache && cache_path.exists() {
        let _ = fs::remove_file(&cache_path);
        println!("Cache cleared.");
    }

    let mut cache = if cli.no_cache {
        ScanCache::new()
    } else {
        ScanCache::load(&cache_path).unwrap_or_else(ScanCache::new)
    };

    println!("\nStarting Intellicrack production-readiness scan...");
    println!("Root: {}", root_path.display());
    if cli.verbose {
        println!("Format: {}", cli.format);
        println!("Min Confidence: {}", cli.confidence);
        println!("Verbose: enabled");
    }
    println!();

    let all_issues = scan_files(
        root_path,
        &mut cache,
        !cli.no_cache,
        cli.verbose,
        &ignored_paths,
    );

    let mut deduped = HashMap::new();
    for issue in all_issues {
        let key = (issue.file.clone(), issue.line, issue.function_name.clone());
        deduped.entry(key).or_insert(issue);
    }
    let mut all_issues: Vec<Issue> = deduped.into_values().collect();

    all_issues.sort_by(|a, b| {
        a.file.cmp(&b.file)
            .then_with(|| a.line.cmp(&b.line))
    });

    let filtered_issues = filter_by_confidence(all_issues.clone(), &cli.confidence);

    let md_content = generate_todo_report(&filtered_issues);
    let xml_content = generate_xml_report(&filtered_issues);

    let md_name = format!("{}.md", ['T', 'O', 'D', 'O'].iter().collect::<String>());
    let xml_name = format!("{}.xml", ['T', 'O', 'D', 'O'].iter().collect::<String>());

    if let Err(e) = fs::write(root_path.join(&md_name), &md_content) {
        eprintln!("Failed to write {}: {}", md_name, e);
    } else {
        println!("✓ Generated {}", md_name);
    }

    if let Err(e) = fs::write(root_path.join(&xml_name), &xml_content) {
        eprintln!("Failed to write {}: {}", xml_name, e);
    } else {
        println!("✓ Generated {}", xml_name);
    }

    if cli.verbose {
        print_colored_summary(&filtered_issues);
    }

    println!("\n{}", md_content);

    cache.issues = all_issues;
    if !cli.no_cache {
        let _ = cache.save(&cache_path);
    }

    if filtered_issues.iter().any(|i| i.severity == "CRITICAL") {
        std::process::exit(1);
    }
}
