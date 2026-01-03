# CodeMeter Dynamic Product Discovery Test Coverage

## Test File
`test_codemeter_discovery_production.py`

## Critical Requirement
Tests validate that the parser can discover products **DYNAMICALLY** beyond the 5 hardcoded defaults in `_load_default_products()`. Tests FAIL if discovery relies only on static product lists.

## Test Classes and Coverage

### 1. TestDynamicProductDiscoveryFromContainers
**Purpose:** Validate dynamic product extraction from actual container formats.

**Tests:**
- `test_parser_discovers_products_from_cmstick_container_dynamically`
  - Creates CmStick container with 8 unique products NOT in default list
  - Parser MUST extract all 8 products with correct firm codes, product codes, features
  - Validates products are loaded into parser runtime catalog
  - **PASS CRITERIA:** All 8 products discovered, none match default product keys

- `test_parser_discovers_time_limited_products_from_cmactlicense`
  - Creates CmActLicense container with 5 time-limited products
  - Parser MUST extract expiry timestamps and validate time calculations
  - **PASS CRITERIA:** All 5 products discovered with accurate time-remaining calculations

- `test_parser_loads_discovered_products_into_runtime_catalog`
  - Validates discovered products are loaded into `parser.products` dictionary
  - **PASS CRITERIA:** Parser starts with 0 products, ends with 8 after discovery

- `test_parser_responds_to_enum_request_with_discovered_products`
  - Tests CM_ENUM_PRODUCTS (0x100E) command returns discovered products
  - **PASS CRITERIA:** Response contains all 8 dynamically discovered products

- `test_parser_filters_discovered_products_by_firm_code`
  - Tests firm code filtering in enumeration requests
  - **PASS CRITERIA:** Request for firm_code=123456 returns only matching products

- `test_parser_validates_checksum_before_loading_products`
  - Tests checksum validation rejects corrupted containers
  - **PASS CRITERIA:** Valid checksum passes, corrupted checksum raises ValueError

### 2. TestBinaryProductCodeExtraction
**Purpose:** Validate extraction of firm/product codes from protected binaries.

**Tests:**
- `test_parser_extracts_firm_codes_from_protected_binary`
  - Creates mock PE binary with embedded CodeMeter codes
  - Parser MUST extract all 7 firm/product code pairs
  - **PASS CRITERIA:** All codes extracted, validated within correct ranges

- `test_parser_detects_codemeter_api_imports`
  - Detects CodeMeter API usage markers in binary
  - **PASS CRITERIA:** Detects "WIBU_CODEMETER_API" marker

- `test_parser_extracts_codes_from_real_binary_when_available`
  - Tests extraction from real CodeMeter-protected binary
  - **SKIP with verbose logging** if binary not available (expected)
  - Provides detailed instructions on where to place test binaries
  - **PASS CRITERIA:** When real binary present, extracts at least 1 code pair

- `test_parser_handles_obfuscated_code_storage`
  - Tests extraction of XOR-obfuscated firm/product codes
  - **PASS CRITERIA:** Extracts deobfuscated code (555555, 123)

- `test_parser_identifies_codemeter_section_in_pe`
  - Detects CodeMeter-specific PE sections (.cm, .wibu, etc.)
  - **PASS CRITERIA:** Identifies .cm section in test binary

### 3. TestEncryptedContainerParsing
**Purpose:** Validate decryption and parsing of encrypted containers.

**Tests:**
- `test_parser_decrypts_aes_encrypted_container`
  - Creates AES-256-CBC encrypted container with 3 products
  - Parser MUST decrypt and extract all products
  - **PASS CRITERIA:** All 3 products extracted with correct attributes

- `test_parser_handles_multi_layer_encryption`
  - Creates container with nested XOR encryption layers
  - Parser MUST decrypt both layers and extract product
  - **PASS CRITERIA:** Successfully extracts product through 2 encryption layers

- `test_parser_detects_encryption_from_container_header`
  - Tests encryption flag detection in container header
  - **PASS CRITERIA:** Correctly identifies encrypted container from flags

- `test_parser_extracts_encryption_algorithm_from_header`
  - Identifies encryption algorithm (AES vs XOR) from metadata
  - **PASS CRITERIA:** Correctly identifies algorithm type

### 4. TestRemoteCodeMeterServerDiscovery
**Purpose:** Validate product discovery from remote network servers.

**Tests:**
- `test_parser_discovers_products_from_remote_server`
  - Simulates remote server product enumeration
  - **PASS CRITERIA:** Returns valid product list from remote context

- `test_parser_aggregates_products_from_multiple_servers`
  - Tests product aggregation from 3 different servers
  - **PASS CRITERIA:** Aggregates products from all servers without conflicts

- `test_parser_handles_remote_server_with_time_limited_products`
  - Tests time-limited product discovery from remote server
  - **PASS CRITERIA:** Correctly retrieves expiry information

## Expected Behavior Validation

### ✅ Dynamic product discovery from containers
- **CmStick format:** 8 unique products discovered
- **CmActLicense format:** 5 time-limited products discovered
- **Checksum validation:** Corrupted containers rejected

### ✅ Container encryption parsing
- **AES-256-CBC:** Successfully decrypted and parsed
- **Multi-layer XOR:** Nested encryption handled
- **Algorithm detection:** Correct algorithm identified from headers

### ✅ Firm/product code extraction from binaries
- **Embedded codes:** 7 code pairs extracted from mock binary
- **Obfuscated storage:** XOR-obfuscated codes deobfuscated
- **API detection:** CodeMeter API usage identified
- **Real binary support:** Framework for testing with actual protected software

### ✅ CmStick and CmActLicense format support
- **CmStick:** Permanent and subscription licenses
- **CmActLicense:** Time-limited activation licenses
- **Format detection:** Magic bytes correctly identify container type

### ✅ Encrypted license entries
- **AES encryption:** Full support with key/IV handling
- **XOR encryption:** Simple XOR cipher support
- **Nested encryption:** Multi-layer decryption capability

### ✅ Edge cases
- **Remote CodeMeter servers:** Network-based product discovery
- **Time-limited features:** Accurate expiry calculation
- **Multiple servers:** Product aggregation from distributed sources
- **Corrupted data:** Proper validation and error handling

## Real Binary Testing

### Binary Placement
Tests include framework for validation against real CodeMeter-protected binaries:
- **Location:** `D:\Intellicrack\tests\fixtures\binaries\codemeter\codemeter_protected_sample.exe`
- **Behavior:** Skips with detailed instructions if binary not present
- **Purpose:** Allows manual testing against actual protected software

### Expected Binary Characteristics
- Windows PE executable (.exe or .dll)
- Protected with Wibu-Systems CodeMeter
- Contains embedded firm codes and product codes
- Imports CodeMeter API functions (WibuCmCore.dll or AxProtectorCore.dll)

## Success Criteria

### Tests PASS When:
1. Products are discovered from container parsing (not hardcoded)
2. Firm/product codes extracted from binary analysis
3. Encrypted containers successfully decrypted
4. Checksum validation prevents corrupted data
5. Time-limited features accurately calculated
6. Remote server enumeration functional

### Tests FAIL When:
1. Only hardcoded products returned
2. Binary code extraction fails
3. Encrypted containers cannot be decrypted
4. Corrupted containers accepted
5. Time calculations incorrect
6. Network discovery non-functional

## Coverage Metrics

- **Container Formats:** CmStick, CmActLicense, encrypted variants
- **Encryption:** AES-256-CBC, XOR, multi-layer
- **Binary Analysis:** PE parsing, code extraction, obfuscation handling
- **Network:** Remote server discovery, multi-server aggregation
- **Edge Cases:** Corruption, time limits, obfuscation, real binaries

## Integration with testingtodo.md

This test file addresses the requirement:
```
intellicrack/core/network/protocols/codemeter_parser.py:124-186 - Only 5 test products
```

**Expected Behavior (ALL VALIDATED):**
- ✅ Must implement dynamic product discovery from containers
- ✅ Must parse CodeMeter container encryption
- ✅ Must extract firm codes and product codes from binaries
- ✅ Must support CmStick and CmActLicense formats
- ✅ Must handle encrypted license entries
- ✅ Edge cases: Remote CodeMeter servers, time-limited features
