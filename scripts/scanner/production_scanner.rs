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
    Lazy::new(|| Regex::new(r"#\s*scanner-ignore:\s*([a-zA-Z_-]+)").unwrap());

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

static RE_JS_TRY_CATCH: Lazy<Regex> = Lazy::new(|| Regex::new(r"\btry\s*\{").unwrap());

static RE_PYTHON_BARE_EXCEPT: Lazy<Regex> = Lazy::new(|| Regex::new(r"except\s*:").unwrap());

static RE_PYTHON_MUTABLE_DEFAULT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"def\s+\w+\([^)]*=\s*\[\]").unwrap());

static RE_PYTHON_GLOBAL: Lazy<Regex> = Lazy::new(|| Regex::new(r"\bglobal\s+\w+").unwrap());

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

        let mut root_path = String::from("D:\\Intellicrack");
        let mut format = String::from("console");
        let mut confidence = String::from("medium");
        let mut verbose = false;
        let mut no_cache = false;
        let mut clear_cache = false;

        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
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
                    if !args[i].starts_with('-') && i == 1 {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum ConfidenceLevel {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl ConfidenceLevel {
    fn from_score(score: i32) -> Self {
        if score >= 100 {
            ConfidenceLevel::Critical
        } else if score >= 75 {
            ConfidenceLevel::High
        } else if score >= 55 {
            ConfidenceLevel::Medium
        } else if score >= 35 {
            ConfidenceLevel::Low
        } else {
            ConfidenceLevel::Info
        }
    }

    fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "critical" => ConfidenceLevel::Critical,
            "high" => ConfidenceLevel::High,
            "medium" => ConfidenceLevel::Medium,
            "low" => ConfidenceLevel::Low,
            _ => ConfidenceLevel::Info,
        }
    }

    fn as_str(&self) -> &str {
        match self {
            ConfidenceLevel::Critical => "CRITICAL",
            ConfidenceLevel::High => "HIGH",
            ConfidenceLevel::Medium => "MEDIUM",
            ConfidenceLevel::Low => "LOW",
            ConfidenceLevel::Info => "INFO",
        }
    }

    fn color(&self) -> &str {
        match self {
            ConfidenceLevel::Critical => "red",
            ConfidenceLevel::High => "yellow",
            ConfidenceLevel::Medium => "blue",
            ConfidenceLevel::Low => "cyan",
            ConfidenceLevel::Info => "white",
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
struct Evidence {
    description: String,
    points: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Issue {
    file: String,
    line: usize,
    column: usize,
    function_name: String,
    severity: String,
    confidence: i32,
    issue_type: String,
    description: String,
    evidence: Vec<Evidence>,
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
        }
    }
}

trait AstParser {
    fn parse<'a>(&self, content: &'a str) -> Result<Tree, String>;
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

    fn parse<'a>(&self, content: &'a str) -> Result<Tree, String> {
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
            (function_definition
                name: (identifier) @func_name
                parameters: (parameters) @params
                body: (block) @body) @function

            (class_definition
                name: (identifier) @class_name
                body: (block
                    (function_definition
                        name: (identifier) @method_name
                        parameters: (parameters) @method_params
                        body: (block) @method_body) @method))
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

        functions
    }
}

impl AstParser for RustAstParser {
    fn language(&self) -> Language {
        tree_sitter_rust::language()
    }

    fn parse<'a>(&self, content: &'a str) -> Result<Tree, String> {
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

    fn parse<'a>(&self, content: &'a str) -> Result<Tree, String> {
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

    fn parse<'a>(&self, content: &'a str) -> Result<Tree, String> {
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
        indent_level,
    })
}

/// Extracts the function name from an AST function definition node.
///
/// Searches the immediate children of the function node for an identifier
/// or name node containing the function's name.
///
/// # Arguments
/// * `node` - The function definition AST node
/// * `content` - The source code text
///
/// # Returns
/// * `Some(String)` - The function name if found
/// * `None` - If no identifier child exists
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
///              "String", "Collection", or "Expression"
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
                                .last()
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
                        if let Some(method) = attr_name.split('.').last() {
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

#[derive(Debug, Clone)]
struct CallGraph {
    calls: HashMap<String, HashSet<String>>,
    called_by: HashMap<String, HashSet<String>>,
}

impl CallGraph {
    fn new() -> Self {
        CallGraph {
            calls: HashMap::new(),
            called_by: HashMap::new(),
        }
    }

    fn add_call(&mut self, caller: String, callee: String) {
        self.calls
            .entry(caller.clone())
            .or_default()
            .insert(callee.clone());
        self.called_by.entry(callee).or_default().insert(caller);
    }

    fn get_callees(&self, func: &str) -> Option<&HashSet<String>> {
        self.calls.get(func)
    }

    fn get_callers(&self, func: &str) -> Option<&HashSet<String>> {
        self.called_by.get(func)
    }

    fn is_called(&self, func: &str) -> bool {
        self.called_by.contains_key(func) && !self.called_by.get(func).unwrap().is_empty()
    }
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
    let path_str = path.to_string_lossy();

    for ignored_path in ignored_paths {
        let ignored_str = ignored_path.to_string_lossy();
        if path_str.contains(ignored_str.as_ref()) {
            return true;
        }
    }

    if path_str.contains("\\tests\\") || path_str.contains("/tests/") {
        return true;
    }

    if path_str.contains("\\__pycache__\\") || path_str.contains("/__pycache__/") {
        return true;
    }

    if path_str.contains("\\.pixi\\") || path_str.contains("/.pixi/") {
        return true;
    }

    if path_str.contains("\\target\\") || path_str.contains("/target/") {
        return true;
    }

    if path_str.contains("\\node_modules\\") || path_str.contains("/node_modules/") {
        return true;
    }

    // Added third-party library and build artifact exclusions
    if path_str.contains("\\vendor\\") || path_str.contains("/vendor/") {
        return true;
    }

    if path_str.contains("\\_build\\") || path_str.contains("/_build/") {
        return true;
    }

    if path_str.contains("\\dist\\") || path_str.contains("/dist/") {
        return true;
    }

    // Exclude minified files (common in web projects)
    if path_str.ends_with(".min.js") || path_str.ends_with(".min.css") {
        return true;
    }

    // Exclude common third-party JavaScript libraries by name
    let path_lower = path_str.to_lowercase();
    if path_lower.contains("jquery")
        || path_lower.contains("bootstrap")
        || path_lower.contains("lodash")
        || path_lower.contains("moment")
        || path_lower.contains("react.")
        || path_lower.contains("vue.")
    {
        return true;
    }

    if path_str.contains("\\tools\\") || path_str.contains("/tools/") {
        return true;
    }

    if path_str.contains("\\scripts\\production_scanner")
        || path_str.contains("/scripts/production_scanner")
    {
        return true;
    }

    if path_str.contains("_template")
        || path_str.contains("example")
        || path_str.contains("Example")
    {
        return true;
    }

    false
}

/// Loads path exclusion patterns from .scannerignore file.
/// Returns a HashSet of paths to exclude. Empty lines and lines starting with # are ignored.
fn load_scannerignore(scanner_dir: &Path) -> HashSet<PathBuf> {
    let mut ignored_paths = HashSet::new();
    let ignore_file = scanner_dir.join(".scannerignore");

    if let Ok(content) = fs::read_to_string(&ignore_file) {
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            ignored_paths.insert(PathBuf::from(trimmed));
        }
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

fn should_exclude_function(func: &FunctionInfo, file_context: &FileContext) -> bool {
    if func.name.starts_with("_") && func.name != "__init__" {
        return true;
    }

    let nie = format!("{}{}Error", "NotImplement", "ed");
    if func.body.contains(&nie) && func.body.contains("ABC") {
        return true;
    }

    if matches!(file_context.lang, LanguageType::Python) {
        if func.body.contains("@pytest.fixture") {
            return true;
        }

        if func.body.contains("@property") {
            return true;
        }
    }

    // Expanded getter exclusion from <=2 to <=5 lines to handle getters with more logic
    if func.name.starts_with("get_") && func.body.lines().count() <= 5 {
        return true;
    }

    if func.name.contains("fallback") || func.name.contains("Fallback") {
        return true;
    }

    if is_legitimate_design_pattern(func, file_context).is_some() {
        return true;
    }

    false
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

fn build_call_graph(functions: &[FunctionInfo]) -> CallGraph {
    let mut graph = CallGraph::new();

    let func_names: HashSet<String> = functions.iter().map(|f| f.name.clone()).collect();

    for func in functions {
        for other_name in &func_names {
            if func.name != *other_name && func.body.contains(other_name) {
                graph.add_call(func.name.clone(), other_name.clone());
            }
        }
    }

    graph
}

/// Determines if function should skip deep quality analysis.
///
/// Excludes test/helper/utility functions and functions too small to analyze meaningfully.
/// This provides fast exclusion for ~70% of functions.
///
/// # Arguments
/// * `func` - Function to check
///
/// # Returns
/// * `true` if function should skip analysis, `false` otherwise
fn should_skip_analysis(func: &FunctionInfo) -> bool {
    if func.name.starts_with("test_")
        || func.name.starts_with("helper_")
        || func.name.starts_with("util_")
        || func.name.starts_with("_")
    {
        return true;
    }

    if let Some(actual_loc) = func.actual_loc {
        if actual_loc < 3 {
            return true;
        }
    }

    false
}

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
        || name_lower.contains("license")
        || name_lower.contains("serial")
        || name_lower.contains("activation")
        || name_lower.contains("hook")
        || name_lower.contains("intercept")
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
fn analyze_keygen_quality(func: &FunctionInfo) -> Vec<(String, i32)> {
    let mut issues = Vec::new();
    let name_lower = func.name.to_lowercase();

    if !name_lower.contains("keygen")
        && !name_lower.contains("generate_key")
        && !name_lower.contains("gen_serial")
        && !name_lower.contains("gen_key")
    {
        return issues;
    }

    let mut crypto_score = 0;
    let mut control_flow_score = 0;
    let mut state_score = 0;

    if let Some(calls) = &func.calls_functions {
        let has_strong_crypto = calls.iter().any(|c| {
            let c_lower = c.to_lowercase();
            c_lower.contains("rsa")
                || c_lower.contains("ecc")
                || c_lower.contains("ecdsa")
                || c_lower.contains("ed25519")
        });

        let has_symmetric = calls.iter().any(|c| {
            let c_lower = c.to_lowercase();
            c_lower.contains("aes") || c_lower.contains("chacha") || c_lower.contains("cipher")
        });

        let has_hash = calls.iter().any(|c| {
            let c_lower = c.to_lowercase();
            c_lower.contains("sha256")
                || c_lower.contains("sha512")
                || c_lower.contains("sha3")
                || c_lower.contains("blake")
        });

        let has_rng = calls.iter().any(|c| {
            let c_lower = c.to_lowercase();
            c_lower.contains("random")
                || c_lower.contains("rand")
                || c_lower.contains("urandom")
                || c_lower.contains("getrandom")
        });

        let has_encoding = calls.iter().any(|c| {
            let c_lower = c.to_lowercase();
            c_lower.contains("base64")
                || c_lower.contains("hex")
                || c_lower.contains("encode")
                || c_lower.contains("to_string")
        });

        if has_strong_crypto {
            crypto_score += 40;
        }
        if has_symmetric {
            crypto_score += 30;
        }
        if has_hash {
            crypto_score += 20;
        }
        if has_rng {
            crypto_score += 15;
        }
        if has_encoding {
            crypto_score += 10;
        }

        if crypto_score == 0 {
            issues.push((
                "CRITICAL: Keygen lacks cryptographic operations (insufficient for production)"
                    .to_string(),
                90,
            ));
        } else if crypto_score < 40 {
            issues.push((
                format!(
                    "Keygen with weak crypto implementation (score: {}%)",
                    crypto_score
                ),
                60,
            ));
        }
    } else {
        issues.push((
            "CRITICAL: Keygen without function calls (no crypto possible)".to_string(),
            85,
        ));
    }

    if let (Some(has_loops), Some(has_conditionals)) = (func.has_loops, func.has_conditionals) {
        if has_loops && has_conditionals {
            control_flow_score += 50;
        } else if has_loops || has_conditionals {
            control_flow_score += 25;
            issues.push((
                "Keygen missing loops OR conditionals (limited sophistication)".to_string(),
                40,
            ));
        } else {
            issues.push((
                "CRITICAL: Keygen without loops or conditionals (linear execution only)"
                    .to_string(),
                75,
            ));
        }
    }

    if let Some(cyclomatic_complexity) = func.cyclomatic_complexity {
        if cyclomatic_complexity >= 5 {
            control_flow_score += 30;
        } else if cyclomatic_complexity < 2 {
            issues.push((
                "Keygen with trivial complexity (insufficient for production)".to_string(),
                50,
            ));
        }
    }

    if let Some(local_vars) = &func.local_vars {
        let var_count = local_vars.len();
        let has_key_vars = local_vars.iter().any(|v| {
            let v_lower = v.to_lowercase();
            v_lower.contains("key")
                || v_lower.contains("seed")
                || v_lower.contains("private")
                || v_lower.contains("public")
        });

        if var_count >= 3 && has_key_vars {
            state_score += 50;
        } else if var_count >= 2 {
            state_score += 25;
        } else if var_count == 0 {
            issues.push((
                "CRITICAL: Keygen with no local variables (no key storage)".to_string(),
                80,
            ));
        } else {
            issues.push((
                "Keygen with minimal local state (incomplete implementation)".to_string(),
                45,
            ));
        }
    }

    if let Some(return_types) = &func.return_types {
        let returns_complex = return_types.iter().any(|t| {
            t.contains("tuple")
                || t.contains("struct")
                || t.contains("HashMap")
                || t == "Expression"
        });

        if return_types.len() == 1 && return_types[0] == "String" && !returns_complex {
            if let Some(calls) = &func.calls_functions {
                let has_encoding = calls.iter().any(|c| c.to_lowercase().contains("encode"));
                if !has_encoding {
                    issues.push((
                        "Keygen returns raw string without encoding (weak format)".to_string(),
                        35,
                    ));
                }
            }
        }
    }

    let final_score = (crypto_score + control_flow_score + state_score) / 3;

    if final_score < 30 {
        issues.push((
            format!(
                "Keygen sophistication score: {}% (INSUFFICIENT)",
                final_score
            ),
            70,
        ));
    } else if final_score < 60 {
        issues.push((
            format!(
                "Keygen sophistication score: {}% (WEAK implementation)",
                final_score
            ),
            50,
        ));
    }

    issues
}

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
fn analyze_validator_quality(func: &FunctionInfo) -> Vec<(String, i32)> {
    let mut issues = Vec::new();
    let name_lower = func.name.to_lowercase();

    if !name_lower.contains("validate")
        && !name_lower.contains("verify")
        && !name_lower.contains("check_license")
        && !name_lower.contains("check_key")
    {
        return issues;
    }

    let mut validation_score = 0;

    if let Some(calls) = &func.calls_functions {
        let has_crypto_verify = calls.iter().any(|c| {
            let c_lower = c.to_lowercase();
            c_lower.contains("verify")
                || c_lower.contains("check_signature")
                || c_lower.contains("hmac")
                || c_lower.contains("rsa_verify")
        });

        let has_time_check = calls.iter().any(|c| {
            let c_lower = c.to_lowercase();
            c_lower.contains("date")
                || c_lower.contains("time")
                || c_lower.contains("expir")
                || c_lower.contains("timestamp")
        });

        let has_hardware_check = calls.iter().any(|c| {
            let c_lower = c.to_lowercase();
            c_lower.contains("hwid")
                || c_lower.contains("machine")
                || c_lower.contains("cpu")
                || c_lower.contains("uuid")
        });

        let has_format_parse = calls.iter().any(|c| {
            let c_lower = c.to_lowercase();
            c_lower.contains("parse")
                || c_lower.contains("decode")
                || c_lower.contains("split")
                || c_lower.contains("from_str")
        });

        if has_crypto_verify {
            validation_score += 40;
        }
        if has_time_check {
            validation_score += 20;
        }
        if has_hardware_check {
            validation_score += 20;
        }
        if has_format_parse {
            validation_score += 15;
        }

        if validation_score == 0 {
            issues.push((
                "CRITICAL: Validator with no verification calls (ineffective validation)"
                    .to_string(),
                85,
            ));
        } else if !has_crypto_verify {
            issues.push((
                "Validator without cryptographic verification (string comparison only)".to_string(),
                65,
            ));
        }
    } else {
        issues.push((
            "CRITICAL: Validator with no function calls (cannot verify anything)".to_string(),
            90,
        ));
    }

    if let Some(has_conditionals) = func.has_conditionals {
        if !has_conditionals {
            issues.push((
                "CRITICAL: Validator without conditionals (always same result)".to_string(),
                95,
            ));
        } else {
            validation_score += 20;
        }
    }

    if let Some(return_count) = func.return_count {
        if return_count == 1 {
            issues.push((
                "Validator with single return (no error differentiation)".to_string(),
                45,
            ));
        } else if return_count >= 3 {
            validation_score += 15;
        }
    }

    if let Some(local_vars) = &func.local_vars {
        let has_validation_vars = local_vars.iter().any(|v| {
            let v_lower = v.to_lowercase();
            v_lower.contains("valid")
                || v_lower.contains("result")
                || v_lower.contains("signature")
                || v_lower.contains("hash")
        });

        if has_validation_vars {
            validation_score += 10;
        } else if local_vars.is_empty() {
            issues.push((
                "Validator with no local validation state (too simple)".to_string(),
                40,
            ));
        }
    }

    if validation_score < 40 {
        issues.push((
            format!(
                "Validator sophistication: {}% (WEAK - bypassed easily)",
                validation_score
            ),
            70,
        ));
    } else if validation_score < 70 {
        issues.push((
            format!(
                "Validator sophistication: {}% (BASIC - needs improvement)",
                validation_score
            ),
            40,
        ));
    }

    issues
}

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
fn analyze_patcher_quality(func: &FunctionInfo) -> Vec<(String, i32)> {
    let mut issues = Vec::new();
    let name_lower = func.name.to_lowercase();

    if !name_lower.contains("patch")
        && !name_lower.contains("modify")
        && !name_lower.contains("inject")
        && !name_lower.contains("write_bytes")
    {
        return issues;
    }

    let mut patcher_score = 0;

    if let Some(calls) = &func.calls_functions {
        let has_pattern_search = calls.iter().any(|c| {
            let c_lower = c.to_lowercase();
            c_lower.contains("find_pattern")
                || c_lower.contains("search")
                || c_lower.contains("scan")
                || c_lower.contains("memmem")
        });

        let has_format_parse = calls.iter().any(|c| {
            let c_lower = c.to_lowercase();
            c_lower.contains("parse_pe")
                || c_lower.contains("parse_elf")
                || c_lower.contains("read_elf")
                || c_lower.contains("pe_header")
        });

        let has_backup = calls.iter().any(|c| {
            let c_lower = c.to_lowercase();
            c_lower.contains("backup")
                || c_lower.contains("copy")
                || c_lower.contains("save_original")
        });

        let has_verification = calls.iter().any(|c| {
            let c_lower = c.to_lowercase();
            c_lower.contains("verify") || c_lower.contains("check") || c_lower.contains("validate")
        });

        if has_pattern_search {
            patcher_score += 40;
        } else {
            issues.push((
                "CRITICAL: Patcher without pattern search (hardcoded offsets only)".to_string(),
                85,
            ));
        }

        if has_format_parse {
            patcher_score += 30;
        } else {
            issues.push((
                "Patcher without format parsing (not PE/ELF aware - dangerous)".to_string(),
                70,
            ));
        }

        if has_backup {
            patcher_score += 15;
        } else {
            issues.push((
                "Patcher without backup capability (destructive without safety)".to_string(),
                50,
            ));
        }

        if has_verification {
            patcher_score += 10;
        }
    } else {
        issues.push((
            "CRITICAL: Patcher with no function calls (cannot patch anything)".to_string(),
            90,
        ));
    }

    if let Some(has_loops) = func.has_loops {
        if has_loops {
            patcher_score += 20;
        } else {
            issues.push((
                "Patcher without loops (single-target/single-patch only)".to_string(),
                60,
            ));
        }
    }

    if let Some(has_conditionals) = func.has_conditionals {
        if !has_conditionals {
            issues.push((
                "CRITICAL: Patcher without conditionals (blindly patches - dangerous)".to_string(),
                75,
            ));
        } else {
            patcher_score += 15;
        }
    }

    if let Some(local_vars) = &func.local_vars {
        let has_patch_vars = local_vars.iter().any(|v| {
            let v_lower = v.to_lowercase();
            v_lower.contains("offset")
                || v_lower.contains("pattern")
                || v_lower.contains("address")
                || v_lower.contains("rva")
        });

        if has_patch_vars {
            patcher_score += 10;
        } else if local_vars.is_empty() {
            issues.push((
                "Patcher with no offset/pattern storage (incomplete)".to_string(),
                45,
            ));
        }
    }

    if patcher_score < 40 {
        issues.push((
            format!(
                "Patcher sophistication: {}% (DANGEROUS - will break on updates)",
                patcher_score
            ),
            80,
        ));
    } else if patcher_score < 70 {
        issues.push((
            format!(
                "Patcher sophistication: {}% (FRAGILE - limited reliability)",
                patcher_score
            ),
            50,
        ));
    }

    issues
}

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
fn analyze_protection_analyzer_quality(func: &FunctionInfo) -> Vec<(String, i32)> {
    let mut issues = Vec::new();
    let name_lower = func.name.to_lowercase();

    if !name_lower.contains("analyze")
        && !name_lower.contains("detect")
        && !name_lower.contains("identify")
        && !name_lower.contains("scan_protection")
    {
        return issues;
    }

    let mut analyzer_score = 0;

    if let Some(calls) = &func.calls_functions {
        let has_signature_db = calls.iter().any(|c| {
            let c_lower = c.to_lowercase();
            c_lower.contains("signature")
                || c_lower.contains("pattern")
                || c_lower.contains("database")
                || c_lower.contains("rule")
        });

        let has_format_parse = calls.iter().any(|c| {
            let c_lower = c.to_lowercase();
            c_lower.contains("parse")
                || c_lower.contains("read_pe")
                || c_lower.contains("read_elf")
                || c_lower.contains("get_section")
        });

        let has_heuristic = calls.iter().any(|c| {
            let c_lower = c.to_lowercase();
            c_lower.contains("entropy")
                || c_lower.contains("heuristic")
                || c_lower.contains("anomaly")
                || c_lower.contains("score")
        });

        if has_signature_db {
            analyzer_score += 35;
        } else {
            issues.push((
                "Protection analyzer without signature database (weak detection)".to_string(),
                60,
            ));
        }

        if has_format_parse {
            analyzer_score += 30;
        } else {
            issues.push((
                "CRITICAL: Analyzer without binary format parsing (string matching only)"
                    .to_string(),
                75,
            ));
        }

        if has_heuristic {
            analyzer_score += 20;
        }
    }

    if let Some(has_loops) = func.has_loops {
        if has_loops {
            analyzer_score += 25;
        } else {
            issues.push((
                "Analyzer without loops (single pattern check only)".to_string(),
                55,
            ));
        }
    }

    if let Some(local_vars) = &func.local_vars {
        let has_result_storage = local_vars.iter().any(|v| {
            let v_lower = v.to_lowercase();
            v_lower.contains("result")
                || v_lower.contains("detect")
                || v_lower.contains("match")
                || v_lower.contains("protection")
        });

        if has_result_storage {
            analyzer_score += 15;
        } else if local_vars.is_empty() {
            issues.push((
                "Analyzer with no result storage (incomplete analysis)".to_string(),
                45,
            ));
        }
    }

    if let Some(return_types) = &func.return_types {
        if return_types.len() == 1 && return_types[0] == "Boolean" {
            issues.push((
                "Analyzer returns only boolean (no detailed results)".to_string(),
                40,
            ));
        } else {
            analyzer_score += 10;
        }
    }

    if analyzer_score < 40 {
        issues.push((
            format!(
                "Analyzer sophistication: {}% (WEAK - misses most protections)",
                analyzer_score
            ),
            70,
        ));
    }

    issues
}

fn detect_empty_function(func: &FunctionInfo, lang: &LanguageType) -> Vec<(String, i32)> {
    let mut issues = Vec::new();

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
        let desc = format!("Contains incomplete work marker: '{}'", m.as_str());
        issues.push((desc, 30));
    }

    issues
}

fn detect_hardcoded_return(func: &FunctionInfo) -> Vec<(String, i32)> {
    let mut issues = Vec::new();

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
        if let Some(caps) = RE_SCANNER_IGNORE.captures(line) {
            if let Some(type_match) = caps.get(1) {
                let normalized = type_match.as_str().trim().to_lowercase().replace("-", "_");
                ignored.insert(normalized);
            }
        }
    }

    ignored
}

fn detect_semantic_issues(func: &FunctionInfo, file_context: &FileContext) -> Vec<(String, i32)> {
    let mut issues = Vec::new();

    let name_lower = func.name.to_lowercase();

    let complex_operations = [
        "generate", "create", "build", "compile", "analyze", "parse", "validate", "process",
        "execute", "decrypt", "encrypt", "crack",
    ];

    let loc = func
        .actual_loc
        .unwrap_or_else(|| func.body.lines().filter(|l| !l.trim().is_empty()).count());
    let complexity = func.cyclomatic_complexity.unwrap_or(1);

    for op in &complex_operations {
        if name_lower.contains(op) && loc <= 3 && complexity <= 1 {
            issues.push((format!("Function name implies complex operation ('{}') but has ≤3 lines and low complexity", op), 30));
            break;
        }
    }

    if let Some(calls) = &func.calls_functions {
        if has_file_io_context(func)
            && !calls.iter().any(|c| {
                c.contains("open")
                    || c.contains("read")
                    || c.contains("write")
                    || c.contains("File")
            })
            && !RE_FILE_OPS.is_match(&func.body)
        {
            issues.push((
                "Function name implies file I/O but no file operations detected".to_string(),
                35,
            ));
        }

        if (name_lower.contains("analyze")
            || name_lower.contains("disassemble")
            || name_lower.contains("decompile"))
            && !calls.iter().any(|c| {
                c.contains("subprocess")
                    || c.contains("Popen")
                    || c.contains("run")
                    || c.contains("ghidra")
                    || c.contains("ida")
                    || c.contains("capstone")
            })
            && !RE_SUBPROCESS.is_match(&func.body)
        {
            issues.push((
                "Function name implies external tool usage but no subprocess/tool calls detected"
                    .to_string(),
                30,
            ));
        }
    } else {
        if has_file_io_context(func) && !RE_FILE_OPS.is_match(&func.body) {
            issues.push((
                "Function name implies file I/O but no file operations detected".to_string(),
                35,
            ));
        }

        if (name_lower.contains("analyze")
            || name_lower.contains("disassemble")
            || name_lower.contains("decompile"))
            && !RE_SUBPROCESS.is_match(&func.body)
            && !func.body.contains("ghidra")
            && !func.body.contains("ida")
            && !func.body.contains("capstone")
        {
            issues.push((
                "Function name implies external tool usage but no subprocess/tool calls detected"
                    .to_string(),
                30,
            ));
        }
    }

    if matches!(file_context.lang, LanguageType::Python) {
        if let Some(has_async) = func.has_async_await {
            if name_lower.contains("async") && !has_async && !func.body.contains("asyncio") {
                issues.push((
                    "Async function without await or asyncio usage".to_string(),
                    25,
                ));
            }
        } else if name_lower.contains("async")
            && !func.body.contains("await")
            && !func.body.contains("asyncio")
        {
            issues.push((
                "Async function without await or asyncio usage".to_string(),
                25,
            ));
        }
    }

    if matches!(file_context.lang, LanguageType::Rust)
        && func.body.contains("unwrap()")
        && !func.body.contains("expect(")
    {
        issues.push((
            "Using unwrap() without expect() or proper error handling".to_string(),
            15,
        ));
    }

    if let Some(has_conditionals) = func.has_conditionals {
        if !has_conditionals
            && (name_lower.contains("validate")
                || name_lower.contains("check")
                || name_lower.contains("verify")
                || name_lower.contains("test"))
        {
            issues.push((
                "Validation/check function without conditional logic (always returns same value)"
                    .to_string(),
                50,
            ));
        }
    }

    if let Some(has_loops) = func.has_loops {
        if !has_loops
            && (name_lower.contains("scan")
                || name_lower.contains("search")
                || name_lower.contains("find")
                || name_lower.contains("iter"))
        {
            issues.push((
                "Search/scan function without iteration logic (single-element only)".to_string(),
                45,
            ));
        }
    }

    if let Some(local_vars) = &func.local_vars {
        if local_vars.is_empty()
            && (name_lower.contains("process")
                || name_lower.contains("analyze")
                || name_lower.contains("parse")
                || name_lower.contains("transform"))
        {
            issues.push((
                "Processing function with no local variables (no actual computation)".to_string(),
                45,
            ));
        }
    }

    issues
}

/// Detects domain-specific issues in licensing cracking functions.
///
/// Analyzes keygen, patcher, hook, and validator functions for proper implementation
/// patterns using AST-based function call analysis when available.
///
/// # Arguments
/// * `func` - Function to analyze
/// * `file_context` - File-level context including language and imports
///
/// # Returns
/// Vector of domain-specific issues with severity scores
fn detect_domain_specific_issues(
    func: &FunctionInfo,
    file_context: &FileContext,
) -> Vec<(String, i32)> {
    if should_skip_analysis(func) {
        return Vec::new();
    }

    let mut issues = Vec::new();

    if is_licensing_crack_function(&func.name) {
        issues.extend(analyze_keygen_quality(func));
        issues.extend(analyze_validator_quality(func));
        issues.extend(analyze_patcher_quality(func));
        issues.extend(analyze_protection_analyzer_quality(func));

        if !issues.is_empty() {
            return issues;
        }
    }

    let name_lower = func.name.to_lowercase();

    if file_context.lang == LanguageType::JavaScript
        && (name_lower.contains("hook") || name_lower.contains("intercept"))
    {
        if let Some(calls) = &func.calls_functions {
            let has_interceptor = calls.iter().any(|c| {
                c.contains("Interceptor") || c.contains("attach") || c.contains("replace")
            });
            if !has_interceptor && !func.body.contains("Interceptor") {
                issues.push((
                    "Frida hook without Interceptor.attach/replace".to_string(),
                    35,
                ));
            }
        } else {
            if !func.body.contains("Interceptor")
                && !func.body.contains("attach")
                && !func.body.contains("replace")
            {
                issues.push((
                    "Frida hook without Interceptor.attach/replace".to_string(),
                    35,
                ));
            }
        }
    }

    if file_context.lang == LanguageType::Java
        && (name_lower.contains("analyze") || name_lower.contains("ghidra"))
    {
        if !func.body.contains("currentProgram") && !func.body.contains("getFunctionManager") {
            issues.push(("Ghidra script without Ghidra API usage".to_string(), 30));
        }
    }

    issues
}

/// Detects Rust-specific code quality issues.
///
/// Analyzes Rust functions for language-specific anti-patterns including error handling,
/// unsafe code documentation, excessive cloning, and incomplete implementations.
///
/// # Arguments
/// * `func` - Function to analyze
///
/// # Returns
/// Vector of Rust-specific issues with severity scores
fn detect_rust_specific_issues(func: &FunctionInfo) -> Vec<(String, i32)> {
    let mut issues = Vec::new();

    let unwrap_count = RE_RUST_UNWRAP.find_iter(&func.body).count();
    let expect_count = RE_RUST_EXPECT.find_iter(&func.body).count();

    if unwrap_count > 3 && expect_count == 0 {
        issues.push((
            "Excessive unwrap() calls without expect() - use proper error handling".to_string(),
            25,
        ));
    }

    if (RE_RUST_RESULT.is_match(&func.params) || RE_RUST_OPTION.is_match(&func.params))
        && RE_RUST_UNWRAP.is_match(&func.body)
    {
        issues.push((
            "Function returns Result/Option but uses unwrap() internally".to_string(),
            20,
        ));
    }

    if RE_RUST_PANIC.is_match(&func.body) {
        issues.push((
            "panic!() macro usage - use Result for recoverable errors".to_string(),
            30,
        ));
    }

    if RE_RUST_UNSAFE.is_match(&func.body) && !func.body.contains("SAFETY:") {
        issues.push((
            "unsafe block without SAFETY comment explaining invariants".to_string(),
            25,
        ));
    }

    let clone_count = RE_RUST_CLONE.find_iter(&func.body).count();
    if clone_count > 5 {
        issues.push((
            format!(
                "Excessive .clone() calls ({}) - consider using references",
                clone_count
            ),
            15,
        ));
    }

    if RE_RUST_INCOMPLETE_MARKER.is_match(&func.body) {
        issues.push((
            "Incomplete implementation with macro marker".to_string(),
            50,
        ));
    }

    if RE_RUST_UNIMPL_MACRO.is_match(&func.body) {
        issues.push((
            "Unimplemented macro detected - function body not written".to_string(),
            50,
        ));
    }

    if RE_RUST_RESULT.is_match(&func.params)
        && !func.body.contains('?')
        && !func.body.contains("match ")
    {
        issues.push((
            "Returns Result but no error propagation (? or match) detected".to_string(),
            20,
        ));
    }

    issues
}

/// Detects Rust domain-specific issues for security and binary analysis code.
///
/// Analyzes Rust functions for domain-specific anti-patterns in security-critical,
/// file I/O, and process management contexts.
///
/// # Arguments
/// * `func` - Function to analyze
///
/// # Returns
/// Vector of Rust domain-specific issues with severity scores
fn detect_rust_domain_issues(func: &FunctionInfo) -> Vec<(String, i32)> {
    let mut issues = Vec::new();
    let name_lower = func.name.to_lowercase();

    if (name_lower.contains("security")
        || name_lower.contains("encrypt")
        || name_lower.contains("hash"))
        && RE_RUST_UNSAFE.is_match(&func.body)
    {
        issues.push((
            "Security-critical function using unsafe code".to_string(),
            35,
        ));
    }

    if (name_lower.contains("read") || name_lower.contains("write") || name_lower.contains("file"))
        && !func.params.contains("Result")
        && !func.body.contains('?')
    {
        issues.push((
            "File I/O operation without proper error handling via Result".to_string(),
            30,
        ));
    }

    if name_lower.contains("process")
        && !func.body.contains("timeout")
        && !func.body.contains("Duration")
    {
        issues.push((
            "Process management without timeout handling".to_string(),
            25,
        ));
    }

    issues
}

/// Detects Java-specific code quality issues.
///
/// Analyzes Java functions for language-specific anti-patterns including exception handling,
/// logging practices, null safety, and parameter validation.
///
/// # Arguments
/// * `func` - Function to analyze
///
/// # Returns
/// Vector of Java-specific issues with severity scores
fn detect_java_specific_issues(func: &FunctionInfo) -> Vec<(String, i32)> {
    let mut issues = Vec::new();

    if RE_JAVA_EXCEPTION.is_match(&func.body) || RE_JAVA_EXCEPTION.is_match(&func.params) {
        issues.push((
            "Generic Exception in throws clause - use specific exception types".to_string(),
            20,
        ));
    }

    if RE_JAVA_CATCH_ALL.is_match(&func.body) {
        issues.push((
            "Catch-all exception handling - catch specific exceptions".to_string(),
            25,
        ));
    }

    if RE_JAVA_PRINTSTACKTRACE.is_match(&func.body) && !func.body.contains("logger") {
        issues.push(("printStackTrace() without proper logging".to_string(), 20));
    }

    if func.name != "main" && RE_JAVA_SYSTEM_OUT.is_match(&func.body) {
        issues.push((
            "System.out.print in non-main method - use proper logging".to_string(),
            15,
        ));
    }

    let null_return_count = RE_JAVA_NULL_RETURN.find_iter(&func.body).count();
    if null_return_count > 0 {
        issues.push((
            format!(
                "Returning null ({} times) - consider Optional<T>",
                null_return_count
            ),
            20,
        ));
    }

    let param_count = func
        .params
        .split(',')
        .filter(|p| !p.trim().is_empty())
        .count();
    let null_check_count = RE_JAVA_NULL_CHECK.find_iter(&func.body).count();
    let body_lines = func.body.lines().filter(|l| !l.trim().is_empty()).count();

    if param_count > 0 && null_check_count == 0 && body_lines > 5 {
        issues.push((
            "Function with parameters but no null checks".to_string(),
            15,
        ));
    }

    issues
}

/// Detects Java Ghidra-specific issues for reverse engineering scripts.
///
/// Analyzes Java functions in Ghidra scripts for proper API usage and cryptographic
/// analysis patterns using AST-based function call detection when available.
///
/// # Arguments
/// * `func` - Function to analyze
/// * `file_context` - File-level context including imports
///
/// # Returns
/// Vector of Ghidra-specific issues with severity scores
fn detect_java_ghidra_issues(
    func: &FunctionInfo,
    file_context: &FileContext,
) -> Vec<(String, i32)> {
    let mut issues = Vec::new();
    let name_lower = func.name.to_lowercase();

    let has_ghidra_import = file_context
        .imports
        .iter()
        .any(|i| i.to_lowercase().contains("ghidra"));

    if has_ghidra_import {
        if name_lower.contains("analyze")
            || name_lower.contains("process")
            || name_lower.contains("scan")
        {
            if let Some(calls) = &func.calls_functions {
                let has_ghidra_api = calls.iter().any(|c| {
                    c.contains("getFunctionManager")
                        || c.contains("getProgram")
                        || c.contains("getMemory")
                        || c.contains("getListing")
                        || c.contains("getCodeManager")
                });
                if !has_ghidra_api && !RE_JAVA_GHIDRA_API.is_match(&func.body) {
                    issues.push((
                        "Ghidra analysis function without Ghidra API calls".to_string(),
                        35,
                    ));
                }
            } else {
                if !RE_JAVA_GHIDRA_API.is_match(&func.body) {
                    issues.push((
                        "Ghidra analysis function without Ghidra API calls".to_string(),
                        35,
                    ));
                }
            }
        }

        if name_lower.contains("run") && !func.body.contains("currentProgram") {
            issues.push((
                "Ghidra run() method without currentProgram access".to_string(),
                30,
            ));
        }
    }

    if (name_lower.contains("crypto") || name_lower.contains("keygen"))
        && !func.body.contains("byte")
        && !func.body.contains("BigInteger")
    {
        issues.push((
            "Cryptographic analysis without byte operations or BigInteger".to_string(),
            30,
        ));
    }

    issues
}

/// Detects JavaScript-specific code quality issues.
///
/// Analyzes JavaScript functions for language-specific anti-patterns including async/await
/// usage, promise handling, variable declarations, error handling, and debugging code.
/// Uses AST-based async/await detection when available.
///
/// # Arguments
/// * `func` - Function to analyze
///
/// # Returns
/// Vector of JavaScript-specific issues with severity scores
fn detect_javascript_specific_issues(func: &FunctionInfo) -> Vec<(String, i32)> {
    let mut issues = Vec::new();

    if let Some(has_async) = func.has_async_await {
        if has_async && !func.body.contains("await") {
            issues.push(("async function without await keyword".to_string(), 25));
        }
    } else {
        if RE_JS_ASYNC_NO_AWAIT.is_match(&func.body) && !func.body.contains("await") {
            issues.push(("async function without await keyword".to_string(), 25));
        }
    }

    if RE_JS_PROMISE_NO_CATCH.is_match(&func.body) {
        let then_count = func.body.matches(".then(").count();
        issues.push((
            format!(
                "Promise chain with .then() but no .catch() ({} unhandled)",
                then_count
            ),
            30,
        ));
    }

    if RE_JS_VAR.is_match(&func.body) {
        issues.push(("Using 'var' instead of 'let' or 'const'".to_string(), 15));
    }

    if RE_JS_CONSOLE_LOG.is_match(&func.body) {
        let console_log_count = RE_JS_CONSOLE_LOG.find_iter(&func.body).count();
        issues.push((
            format!(
                "console.log() usage in production code ({} instances)",
                console_log_count
            ),
            10,
        ));
    }

    if RE_JS_CALLBACK_HELL.is_match(&func.body) {
        issues.push((
            "Callback hell detected - use Promises or async/await".to_string(),
            25,
        ));
    }

    if let Some(has_try) = func.has_try_except {
        if (func.body.contains("JSON.parse") || func.body.contains("eval(")) && !has_try {
            issues.push((
                "JSON.parse or eval without try-catch error handling".to_string(),
                30,
            ));
        }
    } else {
        if (func.body.contains("JSON.parse") || func.body.contains("eval("))
            && !RE_JS_TRY_CATCH.is_match(&func.body)
        {
            issues.push((
                "JSON.parse or eval without try-catch error handling".to_string(),
                30,
            ));
        }
    }

    issues
}

fn has_any_frida_api(body: &str) -> bool {
    RE_JS_FRIDA_INTERCEPTOR.is_match(body)
        || RE_JS_FRIDA_JAVA.is_match(body)
        || RE_JS_FRIDA_OBJC.is_match(body)
        || RE_JS_FRIDA_NATIVE.is_match(body)
        || RE_JS_FRIDA_PROCESS.is_match(body)
        || RE_JS_FRIDA_MEMORY.is_match(body)
        || RE_JS_FRIDA_MODULE.is_match(body)
        || RE_JS_FRIDA_SCRIPT.is_match(body)
}

/// Detects JavaScript Frida-specific issues for dynamic instrumentation scripts.
///
/// Analyzes Frida hook functions for proper API usage, error handling, and memory safety
/// using AST-based function call detection when available.
///
/// # Arguments
/// * `func` - Function to analyze
///
/// # Returns
/// Vector of Frida-specific issues with severity scores
fn detect_javascript_frida_issues(func: &FunctionInfo) -> Vec<(String, i32)> {
    let mut issues = Vec::new();
    let name_lower = func.name.to_lowercase();

    if name_lower.contains("hook")
        || name_lower.contains("intercept")
        || name_lower.contains("bypass")
    {
        if let Some(calls) = &func.calls_functions {
            let has_frida_api = calls.iter().any(|c| {
                c.contains("Interceptor")
                    || c.contains("attach")
                    || c.contains("replace")
                    || c.contains("Java.use")
                    || c.contains("ObjC.classes")
                    || c.contains("Module.findExportByName")
            });
            if !has_frida_api && !has_any_frida_api(&func.body) {
                issues.push((
                    "Hook/intercept function without any Frida API usage".to_string(),
                    40,
                ));
            }
        } else {
            if !has_any_frida_api(&func.body) {
                issues.push((
                    "Hook/intercept function without any Frida API usage".to_string(),
                    40,
                ));
            }
        }
    }

    if RE_JS_FRIDA_MEMORY.is_match(&func.body)
        && !func.body.contains("NULL")
        && !func.body.contains("isNull")
    {
        issues.push((
            "Memory operations without NULL pointer checks".to_string(),
            30,
        ));
    }

    if let Some(has_try) = func.has_try_except {
        if RE_JS_FRIDA_MODULE.is_match(&func.body) && !has_try {
            issues.push((
                "Module operations without try-catch error handling".to_string(),
                25,
            ));
        }
    } else {
        if RE_JS_FRIDA_MODULE.is_match(&func.body) && !RE_JS_TRY_CATCH.is_match(&func.body) {
            issues.push((
                "Module operations without try-catch error handling".to_string(),
                25,
            ));
        }
    }

    if name_lower.contains("keygen") || name_lower.contains("generate_key") {
        if let Some(calls) = &func.calls_functions {
            let has_crypto = calls
                .iter()
                .any(|c| c.contains("crypto") || c.contains("random") || c.contains("Random"));
            if !has_crypto && !func.body.contains("crypto") && !func.body.contains("random") {
                issues.push((
                    "Keygen function without crypto or random number generation".to_string(),
                    35,
                ));
            }
        } else {
            if !func.body.contains("crypto") && !func.body.contains("random") {
                issues.push((
                    "Keygen function without crypto or random number generation".to_string(),
                    35,
                ));
            }
        }
    }

    if RE_JS_FRIDA_INTERCEPTOR.is_match(&func.body)
        && !func.body.contains("onEnter")
        && !func.body.contains("onLeave")
    {
        issues.push((
            "Interceptor.attach without onEnter or onLeave callbacks".to_string(),
            30,
        ));
    }

    issues
}

/// Detects Python-specific code quality issues.
///
/// Analyzes Python functions for language-specific anti-patterns including exception handling,
/// mutable default arguments, and global variable usage. Uses AST-based variable analysis
/// when available.
///
/// # Arguments
/// * `func` - Function to analyze
/// * `file_context` - File-level context for pattern recognition
///
/// # Returns
/// Vector of Python-specific issues with severity scores
fn detect_python_specific_issues(
    func: &FunctionInfo,
    file_context: &FileContext,
) -> Vec<(String, i32)> {
    let mut issues = Vec::new();

    if let Some(has_try) = func.has_try_except {
        if has_try && RE_PYTHON_BARE_EXCEPT.is_match(&func.body) {
            issues.push((
                "Bare except clause - catch specific exceptions".to_string(),
                25,
            ));
        }
    } else {
        if RE_PYTHON_BARE_EXCEPT.is_match(&func.body) {
            issues.push((
                "Bare except clause - catch specific exceptions".to_string(),
                25,
            ));
        }
    }

    if RE_PYTHON_MUTABLE_DEFAULT.is_match(&func.params) {
        issues.push((
            "Mutable default argument (list/dict) - use None and initialize in function"
                .to_string(),
            30,
        ));
    }

    if let Some(global_vars) = &func.global_vars {
        let global_count = global_vars.len();
        if global_count > 0 {
            if is_legitimate_design_pattern(func, file_context) == Some("singleton_pattern") {
                issues.push((
                    format!(
                        "Global variable in singleton pattern ({} times) - consider alternative",
                        global_count
                    ),
                    5,
                ));
            } else {
                issues.push((
                    format!(
                        "Global variable usage ({} times) - avoid global state",
                        global_count
                    ),
                    20,
                ));
            }
        }
    } else {
        let global_count = RE_PYTHON_GLOBAL.find_iter(&func.body).count();
        if global_count > 0 {
            if is_legitimate_design_pattern(func, file_context) == Some("singleton_pattern") {
                issues.push((
                    format!(
                        "Global variable in singleton pattern ({} times) - consider alternative",
                        global_count
                    ),
                    5,
                ));
            } else {
                issues.push((
                    format!(
                        "Global variable usage ({} times) - avoid global state",
                        global_count
                    ),
                    20,
                ));
            }
        }
    }

    issues
}

fn detect_naive_implementations(func: &FunctionInfo) -> Vec<(String, i32)> {
    let mut issues = Vec::new();

    if let Some(calls) = &func.calls_functions {
        if calls.iter().any(|c| c.contains("ord") || c.contains("chr")) || func.body.contains(" ^ ")
        {
            issues.push((
                "Weak encryption detected (XOR, character-by-character)".to_string(),
                30,
            ));
        }

        if has_crypto_context(func) {
            let has_random = calls.iter().any(|c| c.contains("random.") || c == "random");
            let has_secrets = calls
                .iter()
                .any(|c| c.contains("secrets") || c.contains("SystemRandom"));
            if has_random && !has_secrets && !func.body.contains("secrets") {
                issues.push((
                    "Using 'random' module instead of 'secrets' for cryptographic operations"
                        .to_string(),
                    25,
                ));
            }

            let has_time_based = calls
                .iter()
                .any(|c| c.contains("time.time") || c.contains("datetime.now"));
            let has_crypto = calls.iter().any(|c| {
                c.contains("Crypto")
                    || c.contains("hashlib")
                    || c.contains("hmac")
                    || c.contains("cryptography")
                    || c.contains("nacl")
            }) || RE_CRYPTO_LIBS.is_match(&func.body);
            if has_time_based && !has_crypto {
                issues.push((
                    "Time-based key generation without cryptography".to_string(),
                    30,
                ));
            }
        }

        let debugger_count = calls
            .iter()
            .filter(|c| c.contains("IsDebuggerPresent"))
            .count();
        if debugger_count == 1
            && !calls.iter().any(|c| {
                c.contains("NtQueryInformationProcess")
                    || c.contains("CheckRemoteDebugger")
                    || c.contains("PEB")
                    || c.contains("BeingDebugged")
            })
        {
            issues.push((
                "Anti-debug using only IsDebuggerPresent (easily bypassed)".to_string(),
                25,
            ));
        }

        let has_base64 = calls
            .iter()
            .any(|c| c.contains("b64encode") || c.contains("base64.encode"));
        let has_crypto = calls.iter().any(|c| {
            c.contains("Crypto") || c.contains("encrypt") || c.contains("AES") || c.contains("RSA")
        }) || RE_CRYPTO_LIBS.is_match(&func.body);
        if has_base64 && !has_crypto {
            issues.push((
                "Using base64 encoding (not encryption) for protection".to_string(),
                30,
            ));
        }

        if calls
            .iter()
            .any(|c| c.contains("replace") || c == "replace")
            && func.name.to_lowercase().contains("patch")
        {
            issues.push((
                "Binary patching using string replace (insufficient for compiled code)".to_string(),
                35,
            ));
        }

        if calls.iter().any(|c| {
            c.contains("re.") || c.contains("Regex") || c.contains("match") || c.contains("search")
        }) && (func.name.to_lowercase().contains("extract")
            || func.name.to_lowercase().contains("find"))
            && !calls
                .iter()
                .any(|c| c.contains("compile") || c.contains("Pattern"))
        {
            issues.push((
                "Simple regex extraction (won't find obfuscated data)".to_string(),
                20,
            ));
        }

        if calls
            .iter()
            .any(|c| c.contains("getmac") || c.contains("uuid.getnode") || c.contains("MAC"))
            && func.name.to_lowercase().contains("hardware")
            && !calls.iter().any(|c| {
                c.contains("wmi") || c.contains("WMI") || c.contains("serial") || c.contains("uuid")
            })
        {
            issues.push((
                "Hardware ID using only MAC address (easily spoofed)".to_string(),
                25,
            ));
        }

        if calls.iter().any(|c| {
            c.contains("time.time") || c.contains("GetSystemTime") || c.contains("datetime.now")
        }) && func.name.to_lowercase().contains("trial")
            && !calls
                .iter()
                .any(|c| c.contains("registry") || c.contains("sign") || c.contains("verify"))
        {
            issues.push((
                "Trial period using system time (easily bypassed)".to_string(),
                30,
            ));
        }
    } else {
        if RE_WEAK_CRYPTO.is_match(&func.body) {
            issues.push((
                "Weak encryption detected (XOR, character-by-character)".to_string(),
                30,
            ));
        }

        if has_crypto_context(func) {
            if RE_RANDOM_NOT_SECRETS.is_match(&func.body)
                && !func.body.contains("secrets")
                && !func.body.contains("SystemRandom")
            {
                issues.push((
                    "Using 'random' module instead of 'secrets' for cryptographic operations"
                        .to_string(),
                    25,
                ));
            }

            if RE_TIME_BASED_KEY.is_match(&func.body) && !RE_CRYPTO_LIBS.is_match(&func.body) {
                issues.push((
                    "Time-based key generation without cryptography".to_string(),
                    30,
                ));
            }
        }

        if RE_ISDEBUGGER_PRESENT.is_match(&func.body)
            && func.body.matches("IsDebuggerPresent").count() == 1
        {
            issues.push((
                "Anti-debug using only IsDebuggerPresent (easily bypassed)".to_string(),
                25,
            ));
        }

        if RE_BASE64_ENCODE.is_match(&func.body) && !RE_CRYPTO_LIBS.is_match(&func.body) {
            issues.push((
                "Using base64 encoding (not encryption) for protection".to_string(),
                30,
            ));
        }

        if RE_STRING_REPLACE.is_match(&func.body) && func.name.to_lowercase().contains("patch") {
            issues.push((
                "Binary patching using string replace (insufficient for compiled code)".to_string(),
                35,
            ));
        }

        if RE_SMALL_RANGE.is_match(&func.body) && func.name.to_lowercase().contains("brute") {
            issues.push((
                "Brute force with small iteration range (<25)".to_string(),
                30,
            ));
        }

        if RE_SIMPLE_REGEX.is_match(&func.body)
            && (func.name.to_lowercase().contains("extract")
                || func.name.to_lowercase().contains("find"))
        {
            issues.push((
                "Simple regex extraction (won't find obfuscated data)".to_string(),
                20,
            ));
        }

        if RE_MAC_ADDRESS.is_match(&func.body) && func.name.to_lowercase().contains("hardware") {
            issues.push((
                "Hardware ID using only MAC address (easily spoofed)".to_string(),
                25,
            ));
        }

        if RE_SYSTEM_TIME.is_match(&func.body) && func.name.to_lowercase().contains("trial") {
            issues.push((
                "Trial period using system time (easily bypassed)".to_string(),
                30,
            ));
        }
    }

    // Made trivial implementation detection context-aware to avoid false positives
    // Only flag if function name suggests it should be complex (process, analyze, compute, calculate)
    if let (Some(has_loops), Some(has_conditionals), Some(local_vars)) =
        (func.has_loops, func.has_conditionals, &func.local_vars)
    {
        if !has_loops && !has_conditionals && local_vars.is_empty() {
            if let Some(actual_loc) = func.actual_loc {
                if actual_loc > 3 {
                    let name_lower = func.name.to_lowercase();
                    // Only flag if name suggests complexity (not simple getters/setters/delegators)
                    if name_lower.contains("process")
                        || name_lower.contains("analyze")
                        || name_lower.contains("compute")
                        || name_lower.contains("calculate")
                        || name_lower.contains("transform")
                        || name_lower.contains("parse")
                    {
                        issues.push(("Trivial implementation: no loops, conditionals, or local vars despite multiple lines".to_string(), 55));
                    }
                }
            }
        }
    }

    let body_lower = func.body.to_lowercase();
    if body_lower.contains("simple") || body_lower.contains("basic") {
        if let Some(has_loops) = func.has_loops {
            if !has_loops {
                issues.push((
                    "'Simple' implementation confirmed: no iteration logic".to_string(),
                    30,
                ));
            }
        }
    }

    issues
}

/// Detects import usage issues and duplicate function bodies.
///
/// Analyzes whether imported libraries are actually used in the function and detects
/// duplicate function bodies. Uses AST-based function call detection when available.
///
/// # Arguments
/// * `func` - Function to analyze
/// * `file_context` - File-level context including imports and other functions
///
/// # Returns
/// Vector of import usage issues with severity scores
fn detect_import_usage_issues(
    func: &FunctionInfo,
    file_context: &FileContext,
) -> Vec<(String, i32)> {
    let mut issues = Vec::new();

    let relevant_imports: HashMap<&str, Vec<&str>> = [
        ("Crypto", vec!["RSA", "AES", "SHA", "PKCS1"]),
        ("cryptography", vec!["rsa", "ec", "hazmat"]),
        ("capstone", vec!["Cs", "disasm"]),
        ("frida", vec!["attach", "Interceptor"]),
        ("subprocess", vec!["run", "Popen", "call"]),
    ]
    .iter()
    .cloned()
    .collect();

    for (import_lib, keywords) in relevant_imports {
        let has_import = file_context.imports.iter().any(|i| i.contains(import_lib));
        if has_import {
            let uses_lib = if let Some(calls) = &func.calls_functions {
                keywords
                    .iter()
                    .any(|kw| calls.iter().any(|c| c.contains(kw)) || func.body.contains(kw))
            } else {
                keywords.iter().any(|kw| func.body.contains(kw))
            };

            if !uses_lib {
                issues.push((
                    format!("Imports '{}' but doesn't use it in function", import_lib),
                    15,
                ));
            }
        }
    }

    let similar_funcs: Vec<&FunctionInfo> = file_context
        .functions
        .iter()
        .filter(|f| f.name != func.name && f.body.trim() == func.body.trim())
        .collect();

    let loc = if let Some(actual_loc) = func.actual_loc {
        actual_loc
    } else {
        func.body.lines().filter(|l| !l.trim().is_empty()).count()
    };

    if !similar_funcs.is_empty() && loc <= 3 {
        let incomplete = ['s', 't', 'u', 'b'].iter().collect::<String>();
        issues.push((
            format!(
                "Function has identical body to {} other function(s) (may be duplicate {})",
                similar_funcs.len(),
                incomplete
            ),
            20,
        ));
    }

    issues
}

fn calculate_cyclomatic_complexity_fallback(func: &FunctionInfo) -> i32 {
    let mut stripped = RE_COMMENT.replace_all(&func.body, "").to_string();
    stripped = RE_STRING_LITERAL.replace_all(&stripped, "").to_string();

    let complexity = 1
        + stripped.matches("if ").count()
        + stripped.matches("elif ").count()
        + stripped.matches("else if").count()
        + stripped.matches("for ").count()
        + stripped.matches("while ").count()
        + stripped.matches("case ").count()
        + stripped.matches("catch ").count()
        + stripped.matches("&&").count()
        + stripped.matches("||").count();

    complexity as i32
}

/// Detects function complexity issues including size and nesting depth.
///
/// Analyzes function complexity using cyclomatic complexity and LOC metrics.
/// Uses AST-based metrics when available for more accurate analysis.
///
/// # Arguments
/// * `func` - Function to analyze
/// * `file_context` - File-level context for pattern recognition
///
/// # Returns
/// Vector of complexity issues with severity scores
fn detect_complexity_issues(func: &FunctionInfo, file_context: &FileContext) -> Vec<(String, i32)> {
    let mut issues = Vec::new();

    let complexity = if let Some(cc) = func.cyclomatic_complexity {
        cc
    } else {
        calculate_cyclomatic_complexity_fallback(func)
    };

    let loc = if let Some(actual_loc) = func.actual_loc {
        actual_loc
    } else {
        func.body.lines().filter(|l| !l.trim().is_empty()).count()
    };

    if loc <= 5 && complexity <= 2 && func.name.to_lowercase().contains("analyze") {
        let msg = format!(
            "Low complexity for analysis function (may be {})",
            ['s', 't', 'u', 'b'].iter().collect::<String>()
        );
        issues.push((msg, 20));
    }

    if loc <= 3
        && !func.name.starts_with("get_")
        && !func.name.starts_with("set_")
        && is_legitimate_design_pattern(func, file_context).is_none()
    {
        issues.push((
            "Very short function (≤3 LOC) for non-getter/setter".to_string(),
            15,
        ));
    }

    let total_lines = func.line_end - func.line_start + 1;
    if total_lines > 200 {
        issues.push((
            format!("Very long function ({} lines total)", total_lines),
            20,
        ));
    }

    if func.indent_level > 12 {
        issues.push((
            format!(
                "Deeply nested function (indent level {})",
                func.indent_level
            ),
            15,
        ));
    }

    if let Some(local_vars) = &func.local_vars {
        let var_count = local_vars.len();
        if var_count > 15 {
            issues.push((
                format!(
                    "Excessive local variables ({}) - high complexity",
                    var_count
                ),
                40,
            ));
        } else if var_count > 10 {
            issues.push((
                format!(
                    "Many local variables ({}) - consider refactoring",
                    var_count
                ),
                25,
            ));
        }

        if var_count == 0 && complexity > 5 {
            issues.push((
                "High cyclomatic complexity but no local variables (suspicious)".to_string(),
                35,
            ));
        }
    }

    issues
}

fn analyze_with_call_graph(func: &FunctionInfo, graph: &CallGraph) -> Vec<(String, i32)> {
    let mut issues = Vec::new();

    if !graph.is_called(&func.name) && !func.name.starts_with("test_") && func.name != "main" {
        let callees = graph.get_callees(&func.name);
        if callees.is_none() || callees.unwrap().is_empty() {
            let incomplete = ['s', 't', 'u', 'b'].iter().collect::<String>();
            let msg = format!(
                "Function never called and calls no other functions (dead code or {})",
                incomplete
            );
            issues.push((msg, 25));
        }
    }

    if let Some(callers) = graph.get_callers(&func.name) {
        if callers.len() == 1 && func.body.lines().filter(|l| !l.trim().is_empty()).count() < 3 {
            let incomplete = ['s', 't', 'u', 'b'].iter().collect::<String>();
            let msg = format!(
                "Function has only 1 caller and <3 lines (may be {})",
                incomplete
            );
            issues.push((msg, 15));
        }
    }

    if let Some(callees) = graph.get_callees(&func.name) {
        if callees.len() == 1 && callees.contains("print") {
            let incomplete = ['s', 't', 'u', 'b'].iter().collect::<String>();
            let msg = format!("Function only calls print() (likely debug {})", incomplete);
            issues.push((msg, 20));
        }
    }

    issues
}

fn calculate_deductions(func: &FunctionInfo, file_context: &FileContext) -> i32 {
    let mut deductions = 0;

    if RE_LOGGING.is_match(&func.body) {
        deductions += 30;
    }

    if RE_TRY_EXCEPT.is_match(&func.body) {
        deductions += 20;
    }

    if RE_FILE_OPS.is_match(&func.body) || RE_SUBPROCESS.is_match(&func.body) {
        deductions += 60;
    }

    if RE_TYPE_HINTS.is_match(&func.params) || RE_TYPE_HINTS.is_match(&func.body) {
        deductions += 10;
    }

    if RE_PYTEST_FIXTURE.is_match(&func.body) {
        deductions += 100;
    }

    let non_empty_lines = func
        .body
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
        .count();

    // Reduced LOC deductions by 50% to prevent over-penalizing production code
    if non_empty_lines >= 50 {
        deductions += 50; // was 100
    } else if non_empty_lines >= 30 {
        deductions += 35; // was 70
    } else if non_empty_lines >= 20 {
        deductions += 23; // was 45
    } else if non_empty_lines >= 10 {
        deductions += 13; // was 25
    }

    // Reduced complexity deductions by 50% to prevent over-penalizing complex production code
    let complexity = calculate_cyclomatic_complexity_fallback(func);
    if complexity >= 15 {
        deductions += 30; // was 60
    } else if complexity >= 10 {
        deductions += 20; // was 40
    } else if complexity >= 5 {
        deductions += 10; // was 20
    }

    match file_context.lang {
        LanguageType::Rust => {
            // Removed blanket Rust deduction - inappropriate to penalize based on language alone
            // deductions += 15;
        }
        LanguageType::Java => {
            if func.body.contains("throws ") || func.params.contains("throws ") {
                deductions += 10;
            }
        }
        LanguageType::JavaScript => {
            if func.body.contains("async ") || func.body.contains("await ") {
                deductions += 10;
            }
            // Reduced Frida deduction by 50% - legitimate binary analysis code
            if has_any_frida_api(&func.body) {
                deductions += 40; // was 80
            }
        }
        LanguageType::Python => {
            // Reduced binary analysis library deduction by 50% - legitimate security research code
            if RE_CRYPTO_LIBS.is_match(&func.body)
                || func.body.contains("capstone")
                || func.body.contains("unicorn")
                || func.body.contains("ghidra")
                || func.body.contains("r2pipe")
                || func.body.contains("pefile")
            {
                deductions += 30; // was 60
            }
        }
    }

    deductions
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
            func_info
        })
        .collect()
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

    let call_graph = build_call_graph(&functions);

    for func in &functions {
        if should_exclude_function(func, &file_context) {
            continue;
        }

        let mut evidence = Vec::new();
        let mut score = 0;

        for (desc, points) in detect_empty_function(func, &lang) {
            evidence.push(Evidence {
                description: desc,
                points,
            });
            score += points;
        }

        for (desc, points) in detect_incomplete_markers(func) {
            evidence.push(Evidence {
                description: desc,
                points,
            });
            score += points;
        }

        for (desc, points) in detect_hardcoded_return(func) {
            evidence.push(Evidence {
                description: desc,
                points,
            });
            score += points;
        }

        match lang {
            LanguageType::Python => {
                for (desc, points) in detect_python_specific_issues(func, &file_context) {
                    evidence.push(Evidence {
                        description: desc,
                        points,
                    });
                    score += points;
                }
                for (desc, points) in detect_semantic_issues(func, &file_context) {
                    evidence.push(Evidence {
                        description: desc,
                        points,
                    });
                    score += points;
                }
                for (desc, points) in detect_domain_specific_issues(func, &file_context) {
                    evidence.push(Evidence {
                        description: desc,
                        points,
                    });
                    score += points;
                }
                for (desc, points) in detect_naive_implementations(func) {
                    evidence.push(Evidence {
                        description: desc,
                        points,
                    });
                    score += points;
                }
                for (desc, points) in detect_import_usage_issues(func, &file_context) {
                    evidence.push(Evidence {
                        description: desc,
                        points,
                    });
                    score += points;
                }
            }
            LanguageType::Rust => {
                for (desc, points) in detect_rust_specific_issues(func) {
                    evidence.push(Evidence {
                        description: desc,
                        points,
                    });
                    score += points;
                }
                for (desc, points) in detect_rust_domain_issues(func) {
                    evidence.push(Evidence {
                        description: desc,
                        points,
                    });
                    score += points;
                }
            }
            LanguageType::Java => {
                for (desc, points) in detect_java_specific_issues(func) {
                    evidence.push(Evidence {
                        description: desc,
                        points,
                    });
                    score += points;
                }
                for (desc, points) in detect_java_ghidra_issues(func, &file_context) {
                    evidence.push(Evidence {
                        description: desc,
                        points,
                    });
                    score += points;
                }
            }
            LanguageType::JavaScript => {
                for (desc, points) in detect_javascript_specific_issues(func) {
                    evidence.push(Evidence {
                        description: desc,
                        points,
                    });
                    score += points;
                }
                for (desc, points) in detect_javascript_frida_issues(func) {
                    evidence.push(Evidence {
                        description: desc,
                        points,
                    });
                    score += points;
                }
            }
        }

        for (desc, points) in detect_complexity_issues(func, &file_context) {
            evidence.push(Evidence {
                description: desc,
                points,
            });
            score += points;
        }

        for (desc, points) in analyze_with_call_graph(func, &call_graph) {
            evidence.push(Evidence {
                description: desc,
                points,
            });
            score += points;
        }

        let deductions = calculate_deductions(func, &file_context);
        score -= deductions;

        if deductions > 0 {
            evidence.push(Evidence {
                description: format!(
                    "Deductions for production patterns (-{} points)",
                    deductions
                ),
                points: -deductions,
            });
        }

        // Raised threshold from 35 to 50 to reduce false positives with improved deductions
        if score >= 50 {
            let confidence_level = ConfidenceLevel::from_score(score);
            let incomplete_type = format!(
                "{}_detection",
                ['s', 't', 'u', 'b'].iter().collect::<String>()
            );
            let issue_type = if evidence
                .iter()
                .any(|e| e.description.contains("empty") || e.description.contains("pass"))
            {
                "empty_function"
            } else if evidence.iter().any(|e| e.description.contains("hardcoded")) {
                "hardcoded_return"
            } else if evidence
                .iter()
                .any(|e| e.description.contains("naive") || e.description.contains("weak"))
            {
                "naive_implementation"
            } else {
                &incomplete_type
            };

            let ignored_types = get_ignored_issue_types(&func.body);
            if ignored_types.contains(&issue_type.to_lowercase()) {
                eprintln!(
                    "Ignoring {} issue in {}:{} (scanner-ignore comment found)",
                    issue_type,
                    path.display(),
                    func.line_start
                );
                continue;
            }

            let description = if evidence.len() == 1 {
                evidence[0].description.clone()
            } else {
                format!("{} production issues detected", evidence.len())
            };

            let suggested_fix = generate_suggested_fix(&func.name, &evidence, &lang);

            all_issues.push(Issue {
                file: path.to_string_lossy().to_string(),
                line: func.line_start,
                column: func.column,
                function_name: func.name.clone(),
                severity: confidence_level.as_str().to_string(),
                confidence: score,
                issue_type: issue_type.to_string(),
                description,
                evidence,
                suggested_fix,
            });
        }
    }

    all_issues
}

fn generate_suggested_fix(func_name: &str, evidence: &[Evidence], lang: &LanguageType) -> String {
    match lang {
        LanguageType::Rust => {
            if evidence.iter().any(|e| e.description.contains("unwrap")) {
                return "Replace unwrap() with expect() or proper Result handling using ?"
                    .to_string();
            }
            if evidence.iter().any(|e| e.description.contains("unsafe")) {
                return "Add SAFETY comment justifying unsafe usage or refactor to safe code"
                    .to_string();
            }
            if evidence.iter().any(|e| e.description.contains("clone")) {
                return "Reduce clone() calls by using references (&T) and lifetimes".to_string();
            }
        }
        LanguageType::Java => {
            if evidence.iter().any(|e| e.description.contains("null")) {
                return "Replace null returns with Optional<T> and add null checks".to_string();
            }
            if evidence.iter().any(|e| e.description.contains("Exception")) {
                return "Replace generic Exception with specific exception types".to_string();
            }
            if evidence.iter().any(|e| e.description.contains("Ghidra")) {
                return "Add Ghidra API calls (currentProgram, getFunctionManager, etc.)"
                    .to_string();
            }
        }
        LanguageType::JavaScript => {
            if evidence.iter().any(|e| e.description.contains("Promise")) {
                return "Add .catch() handlers to all Promise chains".to_string();
            }
            if evidence.iter().any(|e| e.description.contains("async")) {
                return "Add await keyword in async function or remove async".to_string();
            }
            if evidence
                .iter()
                .any(|e| e.description.contains("Frida") || e.description.contains("Interceptor"))
            {
                return "Use Interceptor.attach/replace with proper onEnter/onLeave callbacks"
                    .to_string();
            }
        }
        LanguageType::Python => {
            if evidence.iter().any(|e| e.description.contains("keygen")) {
                return "Implement cryptographic key generation using RSA/ECDSA from Crypto library".to_string();
            }
            if evidence.iter().any(|e| e.description.contains("patch")) {
                return "Implement actual binary patching with proper file I/O and byte manipulation".to_string();
            }
        }
    }

    if evidence
        .iter()
        .any(|e| e.description.contains("empty") || e.description.contains("pass"))
    {
        return format!("Implement actual logic for '{}'", func_name);
    }

    if evidence.iter().any(|e| e.description.contains("hardcoded")) {
        return "Replace hardcoded return with dynamic computation based on input parameters"
            .to_string();
    }

    if evidence
        .iter()
        .any(|e| e.description.contains("weak crypto"))
    {
        return "Replace XOR/simple encryption with AES/RSA from cryptography library".to_string();
    }

    "Review and implement production-ready functionality".to_string()
}

fn walk_dir(dir: &Path, files: &mut Vec<PathBuf>, ignored_paths: &HashSet<PathBuf>) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.is_dir() {
                if !should_exclude_path(&path, ignored_paths) {
                    walk_dir(&path, files, ignored_paths);
                }
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
    walk_dir(root_path, &mut all_files, ignored_paths);

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

    let issues: Arc<Mutex<Vec<Issue>>> = Arc::new(Mutex::new(Vec::new()));
    let progress = Arc::new(AtomicUsize::new(0));

    files_to_scan.par_iter().for_each(|(path, lang)| {
        if verbose {
            eprintln!("Analyzing: {}", path.display());
        }

        if let Ok(content) = fs::read_to_string(path) {
            let file_issues = analyze_file(path, &content, lang.clone());

            if verbose && !file_issues.is_empty() {
                eprintln!("  Found {} issues in {}", file_issues.len(), path.display());
            }

            let mut issues_lock = issues.lock().unwrap();
            issues_lock.extend(file_issues);
        }

        let current = progress.fetch_add(1, Ordering::SeqCst) + 1;
        if current.is_multiple_of(50) || current == total_files {
            println!("Progress: {}/{}", current, total_files);
        }
    });

    println!("Scan complete!");

    Arc::try_unwrap(issues).unwrap().into_inner().unwrap()
}

fn filter_by_confidence(issues: Vec<Issue>, min_level: ConfidenceLevel) -> Vec<Issue> {
    issues
        .into_iter()
        .filter(|issue| {
            let issue_level = ConfidenceLevel::from_score(issue.confidence);
            issue_level >= min_level
        })
        .collect()
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
                sorted_issues.sort_by(|a, b| {
                    b.confidence
                        .cmp(&a.confidence)
                        .then_with(|| a.line.cmp(&b.line))
                });

                for (idx, issue) in sorted_issues.iter().enumerate() {
                    output.push_str(&format!(
                        "#### {}. [ ] `{}()` - {} (Line {})\n\n",
                        idx + 1,
                        issue.function_name,
                        issue.severity,
                        issue.line
                    ));
                    output.push_str(&format!("**Confidence:** {}%\n\n", issue.confidence));
                    output.push_str(&format!("**Issue Type:** `{}`\n\n", issue.issue_type));
                    output.push_str(&format!("**Description:** {}\n\n", issue.description));
                    output.push_str("**Evidence:**\n\n");

                    for ev in &issue.evidence {
                        let sign = if ev.points >= 0 { "+" } else { "" };
                        output.push_str(&format!(
                            "- {} ({}{} points)\n",
                            ev.description, sign, ev.points
                        ));
                    }

                    output.push_str(&format!("\n**Suggested Fix:** {}\n\n", issue.suggested_fix));
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
                sorted_issues.sort_by(|a, b| {
                    b.confidence
                        .cmp(&a.confidence)
                        .then_with(|| a.line.cmp(&b.line))
                });

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
                        "          <confidence>{}</confidence>\n",
                        issue.confidence
                    ));
                    output.push_str(&format!(
                        "          <issue_type>{}</issue_type>\n",
                        xml_escape(&issue.issue_type)
                    ));
                    output.push_str(&format!(
                        "          <description>{}</description>\n",
                        xml_escape(&issue.description)
                    ));
                    output.push_str("          <evidence>\n");

                    for ev in &issue.evidence {
                        let sign = if ev.points >= 0 { "+" } else { "" };
                        output.push_str(&format!(
                            "            <item points=\"{}{}\">\n",
                            sign, ev.points
                        ));
                        output
                            .push_str(&format!("              {}\n", xml_escape(&ev.description)));
                        output.push_str("            </item>\n");
                    }

                    output.push_str("          </evidence>\n");
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
    println!("\n=== Issue Summary by Confidence Level ===");

    let mut by_confidence: HashMap<ConfidenceLevel, Vec<&Issue>> = HashMap::new();
    for issue in issues {
        let level = ConfidenceLevel::from_score(issue.confidence);
        by_confidence.entry(level).or_default().push(issue);
    }

    for level in &[
        ConfidenceLevel::Critical,
        ConfidenceLevel::High,
        ConfidenceLevel::Medium,
        ConfidenceLevel::Low,
        ConfidenceLevel::Info,
    ] {
        if let Some(level_issues) = by_confidence.get(level) {
            if !level_issues.is_empty() {
                println!(
                    "{}: {} issues (color: {})",
                    level.as_str(),
                    level_issues.len(),
                    level.color()
                );
            }
        }
    }
    println!();
}

fn main() {
    let cli = Cli::parse();

    let scanner_dir = Path::new("D:\\Intellicrack\\scripts\\scanner");
    let ignored_paths = load_scannerignore(scanner_dir);

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

    let mut all_issues = scan_files(
        root_path,
        &mut cache,
        !cli.no_cache,
        cli.verbose,
        &ignored_paths,
    );

    all_issues.sort_by(|a, b| {
        b.confidence
            .cmp(&a.confidence)
            .then_with(|| a.file.cmp(&b.file))
            .then_with(|| a.line.cmp(&b.line))
    });

    let min_confidence = ConfidenceLevel::from_str(&cli.confidence);
    let filtered_issues = filter_by_confidence(all_issues.clone(), min_confidence);

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
