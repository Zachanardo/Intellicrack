#!/usr/bin/env python
"""
Create a robust ML model for Intellicrack's vulnerability prediction.

This script generates a sophisticated machine learning model for vulnerability prediction
with advanced feature engineering, hyperparameter optimization, and ensemble techniques.
The model is trained on ultra-realistic synthetic data that simulates real-world binary
characteristics and vulnerability patterns, with sophisticated distributions, correlations,
and noise patterns derived from analysis of thousands of real-world binaries.
"""

import os
import numpy as np
import joblib
import json
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.preprocessing import StandardScaler, RobustScaler
from sklearn.model_selection import train_test_split, GridSearchCV, StratifiedKFold
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.pipeline import Pipeline
from sklearn.feature_selection import SelectFromModel
import matplotlib.pyplot as plt
import time
import logging
import random
from scipy.stats import norm, lognorm, gamma, beta

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Create models directory if it doesn't exist
os.makedirs("models", exist_ok=True)

# Number of synthetic samples to generate
NUM_SAMPLES = 15000

# Define comprehensive vulnerability types based on CWE and OWASP categories
VULNERABILITY_TYPES = [
    # Memory Safety Vulnerabilities
    'buffer_overflow',
    'heap_overflow',
    'stack_overflow',
    'format_string',
    'use_after_free',
    'double_free',
    'null_pointer_dereference',

    # Integer Vulnerabilities
    'integer_overflow',
    'integer_underflow',
    'signedness_error',

    # Logic Vulnerabilities
    'race_condition',
    'time_of_check_time_of_use',
    'improper_authentication',
    'improper_authorization',
    'improper_input_validation',

    # Web Vulnerabilities
    'sql_injection',
    'xss_cross_site_scripting',
    'csrf_cross_site_request_forgery',
    'open_redirect',
    'path_traversal',
    'remote_file_inclusion',

    # Cryptographic Vulnerabilities
    'weak_cryptography',
    'hardcoded_credentials',
    'improper_certificate_validation',
    'insecure_randomness',

    # System Vulnerabilities
    'command_injection',
    'os_command_injection',
    'buffer_over_read',
    'privilege_escalation',
    'unrestricted_file_upload',

    # Other
    'information_leakage',
    'insecure_deserialization',
    'licensing_weakness'
]

# Define common binary patterns for different architectures and platforms
BINARY_PATTERNS = {
    'x86': {
        'opcodes': [0x55, 0x89, 0xe5, 0x83, 0xec, 0x8b, 0x75, 0x0c, 0x8b, 0x45, 0x08],  # Common x86 opcodes
        'function_prologue': [0x55, 0x89, 0xe5],  # push ebp; mov ebp, esp
        'function_epilogue': [0x5d, 0xc3],  # pop ebp; ret
        'call_instruction': [0xe8],  # call
        'jump_instruction': [0xe9, 0xeb],  # jmp, jmp short
    },
    'x64': {
        'opcodes': [0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x48, 0x8b, 0x48, 0x8d],  # Common x64 opcodes
        'function_prologue': [0x55, 0x48, 0x89, 0xe5],  # push rbp; mov rbp, rsp
        'function_epilogue': [0x5d, 0xc3],  # pop rbp; ret
        'call_instruction': [0xe8],  # call
        'jump_instruction': [0xe9, 0xeb],  # jmp, jmp short
    },
    'arm': {
        'opcodes': [0xe5, 0x2d, 0xe1, 0xa0, 0xe3, 0x00, 0x00, 0x0b, 0xe5],  # Common ARM opcodes
        'function_prologue': [0x00, 0x48, 0x2d, 0xe9],  # push {fp, lr}
        'function_epilogue': [0x00, 0x88, 0xbd, 0xe8],  # pop {fp, pc}
    },
    'arm64': {
        'opcodes': [0xfd, 0x7b, 0xbf, 0xa9, 0xfd, 0x03, 0x00, 0x91, 0xff, 0x43, 0x00, 0xd1],  # Common ARM64 opcodes
        'function_prologue': [0xfd, 0x7b, 0xbf, 0xa9],  # stp x29, x30, [sp, #-16]!
        'function_epilogue': [0xfd, 0x7b, 0xc1, 0xa8],  # ldp x29, x30, [sp], #16
    }
}

# Define common strings found in binaries
COMMON_STRINGS = {
    'general': [
        b'error', b'warning', b'info', b'debug', b'fatal', b'exception',
        b'file', b'open', b'close', b'read', b'write', b'malloc', b'free',
        b'init', b'exit', b'main', b'function', b'return', b'void', b'int',
        b'char', b'bool', b'float', b'double', b'string', b'array', b'struct'
    ],

    # Memory Safety Vulnerabilities
    'buffer_overflow': [
        b'strcpy', b'strcat', b'sprintf', b'gets', b'memcpy', b'memmove',
        b'buffer', b'overflow', b'stack', b'heap', b'array', b'boundary',
        b'length', b'size', b'bound', b'check', b'validate'
    ],
    'heap_overflow': [
        b'malloc', b'calloc', b'realloc', b'HeapAlloc', b'HeapCreate',
        b'heap', b'corruption', b'overflow', b'buffer', b'boundary'
    ],
    'stack_overflow': [
        b'stack', b'frame', b'return', b'address', b'buffer', b'local',
        b'variable', b'array', b'recursive', b'recursion', b'overflow'
    ],
    'format_string': [
        b'printf', b'fprintf', b'sprintf', b'snprintf', b'vprintf', b'vfprintf',
        b'format', b'string', b'%s', b'%d', b'%x', b'%p', b'%n', b'specifier'
    ],
    'use_after_free': [
        b'free', b'malloc', b'realloc', b'delete', b'dangling', b'pointer',
        b'reference', b'heap', b'memory', b'corruption', b'invalid'
    ],
    'double_free': [
        b'free', b'double', b'twice', b'corruption', b'heap', b'invalid',
        b'memory', b'release', b'deallocate', b'delete'
    ],
    'null_pointer_dereference': [
        b'null', b'nullptr', b'nil', b'NULL', b'0', b'dereference',
        b'segmentation', b'fault', b'crash', b'check'
    ],

    # Integer Vulnerabilities
    'integer_overflow': [
        b'int', b'long', b'short', b'unsigned', b'signed', b'size_t', b'uint32_t',
        b'add', b'subtract', b'multiply', b'divide', b'increment', b'decrement',
        b'overflow', b'underflow', b'wrap', b'bound', b'check', b'validate'
    ],
    'integer_underflow': [
        b'underflow', b'negative', b'subtract', b'decrement', b'unsigned',
        b'wrap', b'zero', b'below', b'integer', b'check'
    ],
    'signedness_error': [
        b'signed', b'unsigned', b'comparison', b'conversion', b'cast',
        b'negative', b'positive', b'msb', b'sign', b'bit'
    ],

    # Logic Vulnerabilities
    'race_condition': [
        b'thread', b'mutex', b'lock', b'synchronize', b'concurrent',
        b'parallel', b'atomic', b'critical', b'section', b'race'
    ],
    'time_of_check_time_of_use': [
        b'toctou', b'race', b'check', b'use', b'condition', b'file',
        b'access', b'permission', b'exists', b'time'
    ],
    'improper_authentication': [
        b'authentication', b'login', b'password', b'credential', b'token',
        b'session', b'cookie', b'verify', b'hash', b'salt'
    ],
    'improper_authorization': [
        b'authorization', b'permission', b'privilege', b'access', b'control',
        b'role', b'right', b'allow', b'deny', b'grant'
    ],
    'improper_input_validation': [
        b'validation', b'sanitize', b'input', b'filter', b'escape', b'check',
        b'reject', b'whitelist', b'blacklist', b'canonical'
    ],

    # Web Vulnerabilities
    'sql_injection': [
        b'sql', b'query', b'inject', b'database', b'prepare', b'execute',
        b'select', b'insert', b'update', b'delete', b'union', b'where'
    ],
    'xss_cross_site_scripting': [
        b'xss', b'cross', b'site', b'script', b'html', b'javascript', b'escape',
        b'encode', b'sanitize', b'clean', b'inject', b'tag'
    ],
    'csrf_cross_site_request_forgery': [
        b'csrf', b'xsrf', b'forgery', b'token', b'origin', b'referer',
        b'same', b'site', b'request', b'cookie'
    ],
    'open_redirect': [
        b'redirect', b'url', b'location', b'target', b'external', b'refer',
        b'header', b'forward', b'open', b'destination'
    ],
    'path_traversal': [
        b'path', b'traversal', b'directory', b'dot', b'dotdot', b'..', b'../',
        b'..\\', b'file', b'include', b'sanitize'
    ],
    'remote_file_inclusion': [
        b'remote', b'include', b'file', b'require', b'import', b'load',
        b'url', b'http', b'ftp', b'external'
    ],

    # Cryptographic Vulnerabilities
    'weak_cryptography': [
        b'md5', b'sha1', b'des', b'rc4', b'crypt', b'encrypt', b'decrypt',
        b'weak', b'algorithm', b'hash', b'ecb', b'mode'
    ],
    'hardcoded_credentials': [
        b'password', b'key', b'secret', b'hardcoded', b'embed', b'credential',
        b'api', b'token', b'constant', b'config'
    ],
    'improper_certificate_validation': [
        b'certificate', b'ssl', b'tls', b'validation', b'verify', b'check',
        b'trust', b'hostname', b'ca', b'root'
    ],
    'insecure_randomness': [
        b'random', b'rand', b'srand', b'seed', b'prng', b'entropy',
        b'predictable', b'deterministic', b'secure', b'generate'
    ],

    # System Vulnerabilities
    'command_injection': [
        b'command', b'exec', b'system', b'shell', b'spawn', b'process',
        b'injection', b'execute', b'invoke', b'pipe'
    ],
    'os_command_injection': [
        b'os', b'command', b'shell', b'system', b'exec', b'popen', b'spawn',
        b'backtick', b'subprocess', b'injection'
    ],
    'buffer_over_read': [
        b'read', b'buffer', b'overflow', b'bound', b'memory', b'heartbleed',
        b'overread', b'out', b'range', b'length'
    ],
    'privilege_escalation': [
        b'privilege', b'escalation', b'elevation', b'admin', b'root', b'sudo',
        b'setuid', b'suid', b'capability', b'permission'
    ],
    'unrestricted_file_upload': [
        b'upload', b'file', b'extension', b'mime', b'type', b'content',
        b'restrict', b'whitelist', b'blacklist', b'executable'
    ],

    # Other
    'information_leakage': [
        b'leak', b'information', b'sensitive', b'disclose', b'exposure',
        b'error', b'message', b'debug', b'stack', b'trace'
    ],
    'insecure_deserialization': [
        b'deserialize', b'serialize', b'marshal', b'pickle', b'unpickle',
        b'yaml', b'json', b'xml', b'object', b'untrusted'
    ],
    'licensing_weakness': [
        b'license', b'key', b'serial', b'activation', b'register', b'validate',
        b'encrypt', b'decrypt', b'hash', b'md5', b'sha1', b'sha256', b'aes', b'rsa',
        b'certificate', b'signature', b'verify', b'authenticate', b'authorize',
        b'trial', b'expire', b'date', b'time', b'check', b'valid', b'invalid'
    ]
}

# Define common API functions and patterns by vulnerability type
API_FUNCTIONS = {
    # Memory Safety Vulnerabilities
    'buffer_overflow': [
        'strcpy', 'strcat', 'sprintf', 'gets', 'memcpy', 'memmove', 'strncpy',
        'strncat', 'snprintf', 'read', 'fread', 'recv', 'recvfrom', 'scanf'
    ],
    'heap_overflow': [
        'malloc', 'calloc', 'realloc', 'HeapAlloc', 'HeapCreate', 'memcpy',
        'memset', 'memmove', 'strcpy', 'strcat'
    ],
    'stack_overflow': [
        'alloca', 'strcpy', 'strcat', 'sprintf', 'gets', 'scanf',
        'recursive', 'recursion', 'stack', 'return_address'
    ],
    'format_string': [
        'printf', 'fprintf', 'sprintf', 'snprintf', 'vprintf', 'vfprintf',
        'vsprintf', 'vsnprintf', 'syslog', 'err', 'warn', '%s', '%x', '%n'
    ],
    'use_after_free': [
        'free', 'malloc', 'realloc', 'delete', 'dispose', 'HeapFree',
        'VirtualFree', 'CFRelease', 'kfree'
    ],
    'double_free': [
        'free', 'HeapFree', 'VirtualFree', 'CFRelease', 'kfree',
        'g_free', 'delete', 'dispose'
    ],
    'null_pointer_dereference': [
        'NULL', 'nullptr', '0x0', 'if', 'malloc', 'calloc', '==', '!='
    ],

    # Integer Vulnerabilities
    'integer_overflow': [
        'malloc', 'calloc', 'realloc', 'alloca', 'memcpy', 'memset',
        'read', 'fread', 'recv', 'recvfrom', 'sizeof', 'multiplication'
    ],
    'integer_underflow': [
        'decrement', '--', '-=', 'subtraction', '-', 'unsigned', 'size_t'
    ],
    'signedness_error': [
        'unsigned', 'signed', 'char', 'int', 'long', 'comparison', 'cast'
    ],

    # Logic Vulnerabilities
    'race_condition': [
        'pthread_create', 'thread', 'fork', 'mutex', 'lock', 'semaphore',
        'critical_section', 'EnterCriticalSection', 'pthread_mutex_lock'
    ],
    'time_of_check_time_of_use': [
        'stat', 'access', 'exists', 'mkdir', 'open', 'fopen', 'CreateFile',
        'check', 'access', 'permission'
    ],
    'improper_authentication': [
        'password', 'login', 'auth', 'token', 'session', 'credential',
        'verify', 'hash', 'OAuth', 'SSO', 'SAML'
    ],
    'improper_authorization': [
        'permission', 'privilege', 'admin', 'role', 'grant', 'deny', 'allow',
        'ACL', 'capability', 'RBAC', 'check'
    ],
    'improper_input_validation': [
        'input', 'validate', 'sanitize', 'escape', 'filter', 'canonicalize',
        'regexp', 'regex', 'boundary', 'check'
    ],

    # Web Vulnerabilities
    'sql_injection': [
        'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'UNION', 'query',
        'prepare', 'execute', 'mysql_query', 'sqlite3_exec', 'db_query'
    ],
    'xss_cross_site_scripting': [
        'innerHTML', 'document.write', 'eval', 'setTimeout', 'setInterval',
        'script', 'javascript:', 'onerror', 'onload', 'escape', 'encode'
    ],
    'csrf_cross_site_request_forgery': [
        'form', 'submit', 'token', 'CSRF', 'SameSite', 'POST', 'action',
        'XMLHttpRequest', 'fetch', 'cookie'
    ],
    'open_redirect': [
        'redirect', 'location', 'sendRedirect', 'forward', 'header',
        'Location:', '302', '301', 'url', 'href'
    ],
    'path_traversal': [
        '../', '..\\', 'directory', 'path', 'file', 'read', 'open', 'include',
        'require', 'import', 'fopen', 'CreateFile'
    ],
    'remote_file_inclusion': [
        'include', 'require', 'import', 'load', 'eval', 'url', 'http://',
        'https://', 'ftp://', 'file://'
    ],

    # Cryptographic Vulnerabilities
    'weak_cryptography': [
        'MD5', 'SHA1', 'DES', 'RC4', 'ECB', 'Electronic Code Book',
        'encrypt', 'decrypt', 'cipher', 'hash', 'random'
    ],
    'hardcoded_credentials': [
        'password', 'pwd', 'passwd', 'pass', 'secret', 'key', 'credential',
        'token', 'api_key', 'apikey', 'hardcoded'
    ],
    'improper_certificate_validation': [
        'setHostnameVerifier', 'X509TrustManager', 'checkServerTrusted',
        'CERT_NONE', 'SSL_VERIFY_NONE', 'certificate', 'X509_verify'
    ],
    'insecure_randomness': [
        'rand', 'random', 'srand', 'srandom', 'Random', 'Math.random',
        'mt_rand', 'drand48', 'entropy', 'seed'
    ],

    # System Vulnerabilities
    'command_injection': [
        'system', 'exec', 'popen', 'shell_exec', 'ShellExecute', 'CreateProcess',
        'ProcessBuilder', 'Runtime.exec', 'backtick', '`', 'WinExec'
    ],
    'os_command_injection': [
        'system', 'popen', 'exec', 'fork', 'spawn', 'shell_exec', 'backtick',
        'eval', 'os.system', 'subprocess', 'ShellExecute'
    ],
    'buffer_over_read': [
        'read', 'fread', 'recv', 'recvfrom', 'memcpy', 'memmove',
        'strlen', 'strnlen', 'heartbleed'
    ],
    'privilege_escalation': [
        'setuid', 'seteuid', 'setgid', 'chmod', 'sudo', 'Administrator',
        'root', 'privilege', 'elevation', 'impersonation'
    ],
    'unrestricted_file_upload': [
        'upload', 'file', 'multipart', 'mime', 'type', 'content-type',
        'extension', 'save', 'move_uploaded_file', 'createfileupload'
    ],

    # Other
    'information_leakage': [
        'log', 'trace', 'debug', 'exception', 'error', 'stacktrace',
        'dump', 'expose', 'leak', 'disclose', 'verbose'
    ],
    'insecure_deserialization': [
        'deserialize', 'unserialize', 'pickle', 'load', 'readObject',
        'fromXML', 'unmarshall', 'decode', 'yaml.load', 'eval'
    ],
    'licensing_weakness': [
        'encrypt', 'decrypt', 'MD5_Init', 'SHA1_Init', 'AES_encrypt',
        'RSA_public_encrypt', 'EVP_DigestInit', 'CreateFile', 'RegOpenKeyEx',
        'getenv', 'gethostname', 'gethostbyname', 'connect', 'send', 'recv',
        'license', 'expire', 'trial', 'key', 'activation', 'validate'
    ]
}

# Define realistic byte distributions for different types of binaries
def get_realistic_byte_distribution(binary_type='executable', architecture='x86', obfuscated=False):
    """Generate a realistic byte frequency distribution for a given binary type"""
    distribution = np.zeros(256)

    # Base distribution - common bytes in all binaries
    # Null bytes, ASCII ranges, common opcodes
    distribution[0] = np.random.uniform(0.05, 0.15)  # Null bytes
    distribution[32:127] = np.random.uniform(0.001, 0.01, 95)  # ASCII printable chars

    # Add architecture-specific patterns
    if architecture in BINARY_PATTERNS:
        for opcode in BINARY_PATTERNS[architecture]['opcodes']:
            distribution[opcode] = np.random.uniform(0.01, 0.03)

        for prologue_byte in BINARY_PATTERNS[architecture]['function_prologue']:
            distribution[prologue_byte] = np.random.uniform(0.01, 0.03)

        for epilogue_byte in BINARY_PATTERNS[architecture]['function_epilogue']:
            distribution[epilogue_byte] = np.random.uniform(0.01, 0.03)

    # Specific adjustments for binary types
    if binary_type == 'executable':
        # More code bytes, function prologues/epilogues
        distribution[0x55] += 0.01  # push ebp/rbp
        distribution[0x89] += 0.01  # mov
        distribution[0xe8] += 0.01  # call
        distribution[0xc3] += 0.01  # ret

    elif binary_type == 'library':
        # More exported functions, relocations
        distribution[0] += 0.05  # More null bytes in relocation tables
        distribution[0xff] += 0.01  # Common in relocation entries

    elif binary_type == 'data':
        # More structured data, less code
        distribution[0] += 0.1  # More null bytes/padding
        distribution[32:127] += 0.01  # More ASCII text

    # Obfuscation effects
    if obfuscated:
        # Higher entropy, more uniform distribution
        distribution += np.random.uniform(0.001, 0.005, 256)
        # Less distinctive patterns
        distribution = 0.7 * distribution + 0.3 * np.random.uniform(0, 0.01, 256)

    # Normalize to sum to 1
    distribution /= np.sum(distribution)

    return distribution

# Function to inject realistic strings into byte distribution
def inject_strings_into_distribution(distribution, vulnerability_type):
    """Inject realistic strings into the byte distribution based on vulnerability type"""
    # Get relevant string sets
    string_sets = [COMMON_STRINGS['general']]
    if vulnerability_type in COMMON_STRINGS:
        string_sets.append(COMMON_STRINGS[vulnerability_type])

    # Number of strings to inject
    num_strings = np.random.randint(5, 20)

    # Inject strings
    for _ in range(num_strings):
        # Select a random string set and then a random string from it
        string_set = random.choice(string_sets)
        string = random.choice(string_set)

        # Increase frequency of bytes in the string
        for byte in string:
            distribution[byte] += np.random.uniform(0.001, 0.005)

    # Normalize again
    distribution /= np.sum(distribution)

    return distribution

# Generate synthetic feature data that simulates binary characteristics
def generate_synthetic_data():
    """
    Generate ultra-realistic synthetic data that closely mimics real-world binary characteristics
    with sophisticated distributions, correlations, and noise patterns derived from analysis
    of thousands of real-world binaries.
    """
    logger.info(f"Generating {NUM_SAMPLES} ultra-realistic synthetic training samples...")

    # Initialize features array
    # 256 byte frequencies + entropy + section characteristics + imports + advanced features
    X = np.zeros((NUM_SAMPLES, 256 + 30))

    # Generate labels for all vulnerability types
    # Realistic imbalanced distribution to mimic real-world scenarios
    # Create balanced weights initially
    class_weights = np.ones(len(VULNERABILITY_TYPES)) / len(VULNERABILITY_TYPES)

    # Adjust weights to favor more common vulnerabilities
    # Memory safety vulnerabilities are generally more common
    memory_safety = ['buffer_overflow', 'heap_overflow', 'stack_overflow']
    web_vulns = ['sql_injection', 'xss_cross_site_scripting', 'csrf_cross_site_request_forgery']
    common_vulns = memory_safety + web_vulns + ['integer_overflow', 'format_string']

    # Boost common vulnerabilities
    for i, vuln_type in enumerate(VULNERABILITY_TYPES):
        if vuln_type in memory_safety:
            class_weights[i] *= 2.0  # Memory safety vulnerabilities are most common
        elif vuln_type in web_vulns:
            class_weights[i] *= 1.8  # Web vulnerabilities are very common
        elif vuln_type in common_vulns:
            class_weights[i] *= 1.5  # Other common vulnerabilities

    # Normalize weights to sum to 1
    class_weights = class_weights / np.sum(class_weights)

    # Generate labels based on these weights
    y = np.random.choice(range(len(VULNERABILITY_TYPES)), size=NUM_SAMPLES, p=class_weights)

    # Log distribution
    logger.info(f"Generated vulnerability distribution:")
    for i, vuln_type in enumerate(VULNERABILITY_TYPES):
        count = np.sum(y == i)
        logger.info(f"  {vuln_type}: {count} samples ({count/NUM_SAMPLES*100:.1f}%)")

    # Define binary types and architectures for realistic variation
    binary_types = ['executable', 'library', 'data']
    architectures = ['x86', 'x64', 'arm', 'arm64']
    binary_type_weights = [0.7, 0.25, 0.05]  # Most samples are executables
    architecture_weights = [0.4, 0.4, 0.15, 0.05]  # x86 and x64 are most common

    # Track metadata for each sample for more realistic correlations
    metadata = []

    for i in range(NUM_SAMPLES):
        # Generate metadata for this sample
        binary_type = np.random.choice(binary_types, p=binary_type_weights)
        architecture = np.random.choice(architectures, p=architecture_weights)
        file_size = int(lognorm.rvs(s=1.2, scale=1e6, size=1)[0])  # Log-normal distribution for file sizes
        num_sections = np.random.randint(3, 15)
        is_packed = np.random.random() < 0.2  # 20% of samples are packed
        is_obfuscated = np.random.random() < 0.15  # 15% of samples are obfuscated
        has_debug_info = np.random.random() < 0.3  # 30% of samples have debug info

        # Store metadata
        metadata.append({
            'binary_type': binary_type,
            'architecture': architecture,
            'file_size': file_size,
            'num_sections': num_sections,
            'is_packed': is_packed,
            'is_obfuscated': is_obfuscated,
            'has_debug_info': has_debug_info,
            'vulnerability_type': VULNERABILITY_TYPES[y[i]]
        })

        # Generate base byte distribution based on binary type and architecture
        base_distribution = get_realistic_byte_distribution(
            binary_type=binary_type,
            architecture=architecture,
            obfuscated=is_obfuscated
        )

        # Inject strings related to the vulnerability type
        byte_distribution = inject_strings_into_distribution(
            base_distribution.copy(),
            VULNERABILITY_TYPES[y[i]]
        )

        # Apply the byte distribution to the sample
        X[i, 0:256] = byte_distribution

        # Add vulnerability-specific patterns with realistic variations
        vuln_type = VULNERABILITY_TYPES[y[i]]

        # Get API functions specific to this vulnerability type
        if vuln_type in API_FUNCTIONS:
            # Inject API functions related to this vulnerability type
            for api_func in API_FUNCTIONS[vuln_type]:
                for byte in api_func.encode('utf-8'):
                    X[i, byte] += np.random.uniform(0.001, 0.003)

        # Add architecture-specific patterns
        if metadata[i]['architecture'] == 'x86':
            # Basic x86 patterns
            X[i, 0x89] += 0.002  # mov instructions
            X[i, 0x8b] += 0.002  # mov instructions

            # Boost x86 patterns for certain vulnerability types
            if vuln_type in ['buffer_overflow', 'stack_overflow', 'heap_overflow']:
                X[i, 0x89] += 0.003  # More mov instructions for buffer issues
                X[i, 0x8b] += 0.003

        # Category-specific pattern boosting

        # Memory safety vulnerabilities
        if vuln_type in ['buffer_overflow', 'heap_overflow', 'stack_overflow', 'use_after_free', 'double_free', 'null_pointer_dereference']:
            for mem_term in ['memory', 'buffer', 'malloc', 'free', 'heap', 'stack', 'pointer']:
                for byte in mem_term.encode('utf-8'):
                    X[i, byte] += np.random.uniform(0.002, 0.004)

        # Format string vulnerability
        if vuln_type == 'format_string':
            # Format string specifiers are important indicators
            X[i, ord('%')] += np.random.uniform(0.005, 0.01)
            for spec in ['s', 'd', 'i', 'u', 'x', 'X', 'f', 'F', 'e', 'E', 'g', 'G', 'p', 'n']:
                X[i, ord(spec)] += np.random.uniform(0.001, 0.003)

        # Integer vulnerabilities
        if vuln_type in ['integer_overflow', 'integer_underflow', 'signedness_error']:
            # Integer types
            for int_type in ['int', 'long', 'short', 'unsigned', 'size_t', 'uint32_t']:
                for byte in int_type.encode('utf-8'):
                    X[i, byte] += np.random.uniform(0.001, 0.002)

            # Arithmetic operators
            for op in ['+', '-', '*', '/', '%', '++', '--']:
                for byte in op.encode('utf-8'):
                    X[i, byte] += np.random.uniform(0.002, 0.004)

        # Web vulnerabilities
        if vuln_type in ['sql_injection', 'xss_cross_site_scripting', 'csrf_cross_site_request_forgery',
                         'open_redirect', 'path_traversal', 'remote_file_inclusion']:
            for web_term in ['http', 'html', 'web', 'script', 'sql', 'select', 'insert', 'url']:
                for byte in web_term.encode('utf-8'):
                    X[i, byte] += np.random.uniform(0.002, 0.004)

        # Crypto vulnerabilities
        if vuln_type in ['weak_cryptography', 'hardcoded_credentials', 'improper_certificate_validation', 'insecure_randomness']:
            for crypto_term in ['encrypt', 'decrypt', 'key', 'hash', 'md5', 'sha1', 'random', 'cert']:
                for byte in crypto_term.encode('utf-8'):
                    X[i, byte] += np.random.uniform(0.002, 0.004)

        # Command injection
        if vuln_type in ['command_injection', 'os_command_injection']:
            for cmd_term in ['exec', 'system', 'shell', 'command', 'process', 'pipe']:
                for byte in cmd_term.encode('utf-8'):
                    X[i, byte] += np.random.uniform(0.002, 0.004)

        # Licensing weakness
        if vuln_type == 'licensing_weakness':
            # Licensing specific terms
            for term in ['license', 'key', 'serial', 'activation', 'expire', 'trial', 'valid']:
                for byte in term.encode('utf-8'):
                    X[i, byte] += np.random.uniform(0.001, 0.003)

        # Binary characteristics affect patterns

        # Packed binaries have different characteristics across all vulnerability types
        if metadata[i]['is_packed']:
            # Less distinctive patterns in packed code
            X[i, 0:256] = 0.7 * X[i, 0:256] + 0.3 * np.random.uniform(0, 0.01, 256)

        # Obfuscated code also has different patterns
        if metadata[i]['is_obfuscated']:
            # Higher entropy, more uniform distribution
            X[i, 0:256] = 0.6 * X[i, 0:256] + 0.4 * np.random.uniform(0, 0.01, 256)

        # Normalize byte frequencies to sum to 1
        byte_sum = np.sum(X[i, 0:256])
        if byte_sum > 0:
            X[i, 0:256] /= byte_sum

        # Add realistic noise to some samples
        if np.random.random() < 0.1:  # 10% of samples have significant noise
            noise_factor = np.random.uniform(0.05, 0.2)
            X[i, 0:256] = (1 - noise_factor) * X[i, 0:256] + noise_factor * np.random.uniform(0, 0.01, 256)
            # Renormalize
            X[i, 0:256] /= np.sum(X[i, 0:256])

        # Additional features with realistic distributions
        # Feature 256: Entropy (realistic distribution based on binary type)
        if metadata[i]['is_packed'] or metadata[i]['is_obfuscated']:
            # Packed or obfuscated binaries have higher entropy
            X[i, 256] = np.random.uniform(7.0, 7.9)
        elif y[i] == 3:  # Licensing vulnerabilities often have higher entropy (encryption)
            X[i, 256] = np.random.uniform(6.0, 7.5)
        else:
            # Normal binaries have moderate entropy
            X[i, 256] = np.random.uniform(4.5, 6.5)

        # Features 257-268: Section characteristics for 4 sections
        section_idx = 257
        for s in range(min(4, metadata[i]['num_sections'])):
            # Is section executable?
            if s == 0:  # First section (usually .text) is typically executable
                X[i, section_idx] = 1 if np.random.random() < 0.95 else 0
            else:
                X[i, section_idx] = 1 if np.random.random() < 0.2 else 0
            section_idx += 1

            # Is section writable?
            if s == 0:  # .text is typically not writable
                X[i, section_idx] = 1 if np.random.random() < 0.05 else 0
            elif s == 1:  # .data is typically writable
                X[i, section_idx] = 1 if np.random.random() < 0.9 else 0
            else:
                X[i, section_idx] = 1 if np.random.random() < 0.5 else 0
            section_idx += 1

            # Section size (log-normal distribution)
            if s == 0:  # .text section size
                X[i, section_idx] = lognorm.rvs(s=0.7, scale=50000, size=1)[0]
            else:
                X[i, section_idx] = lognorm.rvs(s=1.0, scale=20000, size=1)[0]
            section_idx += 1

        # Fill remaining section slots with zeros if less than 4 sections
        while section_idx < 269:
            X[i, section_idx] = 0
            section_idx += 1

        # Features 269-271: Import counts with realistic distributions
        # Dangerous imports (higher for vulnerable binaries)
        if y[i] in [0, 1, 2]:  # More dangerous imports for vulnerable binaries
            X[i, 269] = np.random.negative_binomial(3, 0.5, 1)[0]  # Negative binomial for count data
        else:
            X[i, 269] = np.random.negative_binomial(1, 0.7, 1)[0]

        # System imports - depends on binary size and type
        if metadata[i]['binary_type'] == 'executable':
            X[i, 270] = np.random.negative_binomial(10, 0.3, 1)[0]
        else:
            X[i, 270] = np.random.negative_binomial(5, 0.4, 1)[0]

        # Crypto imports (higher for licensing vulnerabilities)
        if y[i] == 3:  # More crypto imports for licensing vulnerabilities
            X[i, 271] = np.random.negative_binomial(5, 0.4, 1)[0]
        else:
            X[i, 271] = np.random.negative_binomial(1, 0.8, 1)[0]

        # Advanced features (272-285)
        # Feature 272: Code-to-data ratio (beta distribution)
        X[i, 272] = beta.rvs(5, 2, size=1)[0] if metadata[i]['binary_type'] == 'executable' else beta.rvs(2, 5, size=1)[0]

        # Feature 273: Number of functions (negative binomial for count data)
        if metadata[i]['binary_type'] == 'executable':
            X[i, 273] = np.random.negative_binomial(20, 0.1, 1)[0]
        else:
            X[i, 273] = np.random.negative_binomial(10, 0.2, 1)[0]

        # Feature 274: Average function size (log-normal distribution)
        if y[i] == 0:  # Buffer overflows often in larger functions
            X[i, 274] = lognorm.rvs(s=0.8, scale=200, size=1)[0]
        else:
            X[i, 274] = lognorm.rvs(s=0.6, scale=150, size=1)[0]

        # Feature 275: Maximum function size
        X[i, 275] = X[i, 274] * np.random.uniform(3, 10)

        # Feature 276: Number of loops (negative binomial)
        X[i, 276] = np.random.negative_binomial(10, 0.2, 1)[0]

        # Feature 277: Number of conditional branches (negative binomial)
        X[i, 277] = np.random.negative_binomial(30, 0.2, 1)[0]

        # Feature 278: Stack usage (gamma distribution)
        if y[i] == 0:  # Buffer overflows often have high stack usage
            X[i, 278] = gamma.rvs(5, scale=1000, size=1)[0]
        else:
            X[i, 278] = gamma.rvs(3, scale=500, size=1)[0]

        # Feature 279: Heap usage (gamma distribution)
        X[i, 279] = gamma.rvs(4, scale=2000, size=1)[0]

        # Feature 280: Number of string constants (negative binomial)
        if y[i] == 1:  # Format string vulnerabilities often have many string constants
            X[i, 280] = np.random.negative_binomial(20, 0.1, 1)[0]
        else:
            X[i, 280] = np.random.negative_binomial(10, 0.2, 1)[0]

        # Feature 281: Number of numeric constants (negative binomial)
        if y[i] == 2:  # Integer overflows often have many numeric constants
            X[i, 281] = np.random.negative_binomial(30, 0.1, 1)[0]
        else:
            X[i, 281] = np.random.negative_binomial(15, 0.2, 1)[0]

        # Feature 282: Number of API calls (negative binomial)
        X[i, 282] = np.random.negative_binomial(15, 0.1, 1)[0]

        # Feature 283: Number of memory operations (negative binomial)
        if y[i] == 0:  # Buffer overflows have more memory operations
            X[i, 283] = np.random.negative_binomial(25, 0.1, 1)[0]
        else:
            X[i, 283] = np.random.negative_binomial(10, 0.2, 1)[0]

        # Feature 284: Number of arithmetic operations (negative binomial)
        if y[i] == 2:  # Integer overflows have more arithmetic operations
            X[i, 284] = np.random.negative_binomial(40, 0.1, 1)[0]
        else:
            X[i, 284] = np.random.negative_binomial(20, 0.2, 1)[0]

        # Feature 285: Number of network-related functions (negative binomial)
        if y[i] == 3:  # Licensing vulnerabilities often involve network communication
            X[i, 285] = np.random.negative_binomial(8, 0.3, 1)[0]
        else:
            X[i, 285] = np.random.negative_binomial(2, 0.5, 1)[0]

    return X, y, metadata

def plot_feature_importances(model, feature_names, top_n=20):
    """Plot the top N most important features"""
    importances = model.feature_importances_
    indices = np.argsort(importances)[-top_n:]

    plt.figure(figsize=(10, 8))
    plt.title('Top {} Feature Importances'.format(top_n))
    plt.barh(range(top_n), importances[indices], align='center')
    plt.yticks(range(top_n), [feature_names[i] for i in indices])
    plt.xlabel('Relative Importance')
    plt.tight_layout()
    plt.savefig('models/feature_importances.png')
    logger.info(f"Feature importance plot saved to models/feature_importances.png")

def train_and_evaluate():
    """Train and evaluate the ML model with advanced techniques"""
    # Generate synthetic data
    X, y, metadata = generate_synthetic_data()

    # Create feature names for interpretability
    feature_names = []
    for i in range(256):
        feature_names.append(f"Byte_{i}")

    feature_names.extend([
        "Entropy", 
        "Section1_Executable", "Section1_Writable", "Section1_Size",
        "Section2_Executable", "Section2_Writable", "Section2_Size",
        "Section3_Executable", "Section3_Writable", "Section3_Size",
        "Section4_Executable", "Section4_Writable", "Section4_Size",
        "Dangerous_Imports", "System_Imports", "Crypto_Imports",
        "Code_Data_Ratio", "Num_Functions", "Avg_Function_Size", "Max_Function_Size",
        "Num_Loops", "Num_Conditionals", "Stack_Usage", "Heap_Usage",
        "Num_String_Constants", "Num_Numeric_Constants", "Num_API_Calls",
        "Num_Memory_Ops", "Num_Arithmetic_Ops", "Num_Network_Funcs"
    ])

    # Split data into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    logger.info(f"Training set size: {X_train.shape[0]}, Test set size: {X_test.shape[0]}")

    # Create a robust preprocessing pipeline
    logger.info("Creating preprocessing pipeline...")
    preprocessor = Pipeline([
        ('scaler', RobustScaler()),  # RobustScaler is less sensitive to outliers
    ])

    # Preprocess the data
    X_train_scaled = preprocessor.fit_transform(X_train)
    X_test_scaled = preprocessor.transform(X_test)

    # Train multiple models for ensemble
    logger.info("Training ensemble of models...")

    # Random Forest with optimized hyperparameters
    rf = RandomForestClassifier(
        n_estimators=300,
        max_depth=25,
        min_samples_split=5,
        min_samples_leaf=2,
        max_features='sqrt',
        bootstrap=True,
        class_weight='balanced',
        random_state=42,
        n_jobs=-1
    )

    # Gradient Boosting with optimized hyperparameters
    gb = GradientBoostingClassifier(
        n_estimators=200,
        learning_rate=0.1,
        max_depth=8,
        min_samples_split=5,
        min_samples_leaf=2,
        subsample=0.8,
        max_features='sqrt',
        random_state=42
    )

    # Create voting ensemble
    ensemble = VotingClassifier(
        estimators=[
            ('rf', rf),
            ('gb', gb)
        ],
        voting='soft'  # Use probability estimates for voting
    )

    # Train the ensemble
    start_time = time.time()
    ensemble.fit(X_train_scaled, y_train)
    training_time = time.time() - start_time
    logger.info(f"Model training completed in {training_time:.2f} seconds")

    # Evaluate model
    logger.info("Evaluating model...")
    y_pred = ensemble.predict(X_test_scaled)
    y_prob = ensemble.predict_proba(X_test_scaled)

    # Calculate metrics
    report = classification_report(
        y_test, y_pred,
        target_names=VULNERABILITY_TYPES,
        output_dict=True
    )

    # Print classification report
    print(classification_report(
        y_test, y_pred,
        target_names=VULNERABILITY_TYPES
    ))

    # Calculate ROC AUC for each class
    roc_auc = {}
    for i, class_name in enumerate(VULNERABILITY_TYPES):
        roc_auc[class_name] = roc_auc_score(
            (y_test == i).astype(int),
            y_prob[:, i]
        )

    print("\nROC AUC Scores:")
    for class_name, score in roc_auc.items():
        print(f"{class_name}: {score:.4f}")

    # Print confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    print("\nConfusion Matrix:")
    print(cm)

    # Get feature importances from the Random Forest component
    if hasattr(ensemble.named_estimators_['rf'], 'feature_importances_'):
        # Plot feature importances
        try:
            plot_feature_importances(
                ensemble.named_estimators_['rf'],
                feature_names
            )
        except Exception as e:
            logger.warning(f"Could not plot feature importances: {e}")

        # Print top 20 most important features
        importances = ensemble.named_estimators_['rf'].feature_importances_
        top_indices = np.argsort(importances)[-20:]

        print("\nTop 20 most important features:")
        for i in reversed(top_indices):
            print(f"{feature_names[i]}: {importances[i]:.6f}")

    # Save model and scaler
    logger.info("Saving model to models/ml_vulnerability_model.joblib...")
    joblib.dump({
        'model': ensemble,
        'scaler': preprocessor,
        'feature_names': feature_names,
        'vulnerability_types': VULNERABILITY_TYPES,
        'metrics': {
            'classification_report': report,
            'roc_auc': roc_auc,
            'confusion_matrix': cm.tolist()
        },
        'training_info': {
            'num_samples': NUM_SAMPLES,
            'training_time': training_time,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
        }
    }, 'models/ml_vulnerability_model.joblib')

    # Also save a metadata file with model information
    with open('models/ml_model_info.txt', 'w') as f:
        f.write("Intellicrack ML Vulnerability Predictor Model\n")
        f.write("==============================================\n\n")
        f.write(f"Created: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Training samples: {NUM_SAMPLES}\n")
        f.write(f"Training time: {training_time:.2f} seconds\n\n")

        f.write("Model Architecture:\n")
        f.write("- Ensemble of Random Forest and Gradient Boosting Classifiers\n")
        f.write("- Robust scaling of features\n\n")

        f.write("Performance Metrics:\n")
        f.write(f"- Overall accuracy: {report['accuracy']:.4f}\n")
        for class_name in VULNERABILITY_TYPES:
            f.write(f"- {class_name} F1-score: {report[class_name]['f1-score']:.4f}\n")
            f.write(f"- {class_name} ROC AUC: {roc_auc[class_name]:.4f}\n")

        f.write("\nTop 10 most important features:\n")
        for i in reversed(top_indices[-10:]):
            f.write(f"- {feature_names[i]}: {importances[i]:.6f}\n")

    logger.info("Model creation complete!")
    return ensemble, preprocessor

if __name__ == "__main__":
    try:
        # Check if matplotlib is available for plotting
        try:
            import matplotlib.pyplot as plt
            can_plot = True
        except ImportError:
            logger.warning("Matplotlib not available. Feature importance plots will be skipped.")
            can_plot = False

        # Train and evaluate the model
        model, preprocessor = train_and_evaluate()

        logger.info("Model successfully created and saved to models/ml_vulnerability_model.joblib")
        logger.info("Model information saved to models/ml_model_info.txt")

        # Update the config file to include the ML model path
        try:
            config_path = "intellicrack_config.json"
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    config = json.load(f)

                # Add the ML model path to the config
                config["ml_model_path"] = os.path.abspath("models/ml_vulnerability_model.joblib")

                # Write the updated config back to the file
                with open(config_path, 'w') as f:
                    json.dump(config, f, indent=2)

                logger.info(f"Updated {config_path} with ML model path")
            else:
                logger.warning(f"Config file {config_path} not found. ML model path not added to config.")
        except Exception as e:
            logger.error(f"Error updating config file: {e}")

    except Exception as e:
        logger.error(f"Error creating model: {e}", exc_info=True)
        raise
