import hashlib
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

import capstone
import lief
import z3
from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64

from intellicrack.core.serial_generator import (
    GeneratedSerial,
    SerialConstraints,
    SerialFormat,
    SerialNumberGenerator,
)


@dataclass
class KeyConstraint:
    constraint_type: str
    description: str
    value: Any
    confidence: float
    source_address: Optional[int] = None
    assembly_context: Optional[str] = None


@dataclass
class ValidationRoutine:
    address: int
    size: int
    instructions: List[Tuple[int, str, str]]
    constraints: List[KeyConstraint] = field(default_factory=list)
    algorithm_type: Optional[str] = None
    confidence: float = 0.0
    entry_points: List[int] = field(default_factory=list)
    xrefs: List[int] = field(default_factory=list)


@dataclass
class ExtractedAlgorithm:
    algorithm_name: str
    parameters: Dict[str, Any]
    validation_function: Optional[Callable] = None
    key_format: Optional[SerialFormat] = None
    constraints: List[KeyConstraint] = field(default_factory=list)
    confidence: float = 0.0


class ConstraintExtractor:

    def __init__(self, binary_path: Path):
        self.binary_path = Path(binary_path)
        self.binary = lief.parse(str(binary_path))
        self.constraints: List[KeyConstraint] = []
        self.validation_routines: List[ValidationRoutine] = []
        self.disassembler = None
        self._initialize_disassembler()

    def _initialize_disassembler(self):
        if self.binary.header.machine_type == lief.PE.MACHINE_TYPES.AMD64:
            self.disassembler = capstone.Cs(CS_ARCH_X86, CS_MODE_64)
        else:
            self.disassembler = capstone.Cs(CS_ARCH_X86, CS_MODE_32)
        self.disassembler.detail = True

    def extract_constraints(self) -> List[KeyConstraint]:
        self._find_validation_routines()
        self._analyze_string_references()
        self._analyze_constants()
        self._analyze_comparison_operations()
        self._analyze_mathematical_operations()
        self._detect_checksum_algorithms()
        self._analyze_format_patterns()
        return self.constraints

    def _find_validation_routines(self):
        text_section = self._get_text_section()
        if not text_section:
            return

        code = bytes(text_section.content)
        base_address = text_section.virtual_address

        validation_candidates = []
        for _i, instr in enumerate(self.disassembler.disasm(code, base_address)):
            if self._is_validation_instruction(instr):
                validation_candidates.append(instr.address)

        for candidate_addr in validation_candidates:
            routine = self._extract_routine(candidate_addr, code, base_address)
            if routine:
                self.validation_routines.append(routine)

    def _get_text_section(self):
        for section in self.binary.sections:
            if section.name in [".text", "CODE", "__text"]:
                return section
        if self.binary.sections:
            return self.binary.sections[0]
        return None

    def _is_validation_instruction(self, instr) -> bool:
        validation_mnemonics = {"cmp", "test", "jz", "jnz", "je", "jne", "call"}
        return instr.mnemonic in validation_mnemonics

    def _extract_routine(
        self, start_addr: int, code: bytes, base_address: int
    ) -> Optional[ValidationRoutine]:
        instructions = []
        current_addr = start_addr
        max_instructions = 500

        code_offset = current_addr - base_address
        if code_offset < 0 or code_offset >= len(code):
            return None

        for instr in self.disassembler.disasm(
            code[code_offset:], current_addr
        ):
            instructions.append((instr.address, instr.mnemonic, instr.op_str))

            if instr.mnemonic in {"ret", "retn"}:
                break

            if len(instructions) >= max_instructions:
                break

        if len(instructions) < 3:
            return None

        routine = ValidationRoutine(
            address=start_addr,
            size=len(instructions),
            instructions=instructions,
        )

        self._analyze_routine_for_constraints(routine)
        return routine

    def _analyze_routine_for_constraints(self, routine: ValidationRoutine):
        length_constraints = self._extract_length_constraints(routine)
        routine.constraints.extend(length_constraints)

        charset_constraints = self._extract_charset_constraints(routine)
        routine.constraints.extend(charset_constraints)

        checksum_indicators = self._detect_checksum_in_routine(routine)
        routine.constraints.extend(checksum_indicators)

        routine.algorithm_type = self._identify_algorithm_type(routine)
        routine.confidence = self._calculate_routine_confidence(routine)

    def _extract_length_constraints(
        self, routine: ValidationRoutine
    ) -> List[KeyConstraint]:
        constraints = []

        for addr, mnemonic, operands in routine.instructions:
            if mnemonic == "cmp":
                parts = operands.split(",")
                if len(parts) == 2:
                    try:
                        value = int(parts[1].strip(), 0)
                        if 4 <= value <= 256:
                            constraints.append(
                                KeyConstraint(
                                    constraint_type="length",
                                    description=f"Key length comparison with {value}",
                                    value=value,
                                    confidence=0.7,
                                    source_address=addr,
                                    assembly_context=f"{mnemonic} {operands}",
                                )
                            )
                    except (ValueError, IndexError):
                        continue

        return constraints

    def _extract_charset_constraints(
        self, routine: ValidationRoutine
    ) -> List[KeyConstraint]:
        constraints = []
        numeric_ranges = [(0x30, 0x39)]
        uppercase_ranges = [(0x41, 0x5A)]
        lowercase_ranges = [(0x61, 0x7A)]

        for addr, mnemonic, operands in routine.instructions:
            if mnemonic == "cmp":
                parts = operands.split(",")
                if len(parts) == 2:
                    try:
                        value = int(parts[1].strip(), 0)

                        charset_type = None
                        for low, high in numeric_ranges:
                            if low <= value <= high:
                                charset_type = "numeric"
                                break
                        if not charset_type:
                            for low, high in uppercase_ranges:
                                if low <= value <= high:
                                    charset_type = "uppercase"
                                    break
                        if not charset_type:
                            for low, high in lowercase_ranges:
                                if low <= value <= high:
                                    charset_type = "lowercase"
                                    break

                        if charset_type:
                            constraints.append(
                                KeyConstraint(
                                    constraint_type="charset",
                                    description=f"Character set validation: {charset_type}",
                                    value=charset_type,
                                    confidence=0.75,
                                    source_address=addr,
                                    assembly_context=f"{mnemonic} {operands}",
                                )
                            )
                    except (ValueError, IndexError):
                        continue

        return constraints

    def _detect_checksum_in_routine(
        self, routine: ValidationRoutine
    ) -> List[KeyConstraint]:
        constraints = []

        xor_count = sum(
            1 for _, mnemonic, _ in routine.instructions if mnemonic == "xor"
        )
        add_count = sum(
            1 for _, mnemonic, _ in routine.instructions if mnemonic == "add"
        )
        mul_count = sum(
            1 for _, mnemonic, _ in routine.instructions if mnemonic in {"mul", "imul"}
        )
        shl_count = sum(
            1 for _, mnemonic, _ in routine.instructions if mnemonic in {"shl", "shr"}
        )

        if xor_count > 5:
            constraints.append(
                KeyConstraint(
                    constraint_type="checksum",
                    description="XOR-based checksum detected",
                    value="xor_chain",
                    confidence=0.8,
                    source_address=routine.address,
                )
            )

        if add_count > 10 and mul_count > 2:
            constraints.append(
                KeyConstraint(
                    constraint_type="checksum",
                    description="Polynomial checksum detected",
                    value="polynomial",
                    confidence=0.7,
                    source_address=routine.address,
                )
            )

        if shl_count > 3 and xor_count > 3:
            constraints.append(
                KeyConstraint(
                    constraint_type="checksum",
                    description="CRC-like algorithm detected",
                    value="crc",
                    confidence=0.75,
                    source_address=routine.address,
                )
            )

        return constraints

    def _identify_algorithm_type(self, routine: ValidationRoutine) -> Optional[str]:
        instructions = [mnem for _, mnem, _ in routine.instructions]

        if "div" in instructions and "mod" in str(routine.instructions):
            return "modular_arithmetic"

        if instructions.count("xor") > 8:
            return "xor_cipher"

        if "call" in instructions:
            for _, mnemonic, operands in routine.instructions:
                if mnemonic == "call":
                    if "crc" in operands.lower():
                        return "crc"
                    if "md5" in operands.lower():
                        return "md5"
                    if "sha" in operands.lower():
                        return "sha"

        return "custom"

    def _calculate_routine_confidence(self, routine: ValidationRoutine) -> float:
        score = 0.5

        if routine.constraints:
            score += 0.2

        if routine.algorithm_type and routine.algorithm_type != "custom":
            score += 0.2

        if routine.size > 20:
            score += 0.1

        return min(score, 1.0)

    def _analyze_string_references(self):
        strings = self._extract_strings()

        for string_data in strings:
            if self._is_key_format_pattern(string_data):
                format_type = self._classify_format(string_data)
                self.constraints.append(
                    KeyConstraint(
                        constraint_type="format",
                        description=f"Key format pattern: {format_type}",
                        value=string_data,
                        confidence=0.85,
                    )
                )

    def _extract_strings(self) -> List[str]:
        strings = []
        for section in self.binary.sections:
            content = bytes(section.content)
            current_string = bytearray()

            for byte in content:
                if 32 <= byte < 127:
                    current_string.append(byte)
                else:
                    if len(current_string) >= 4:
                        try:
                            strings.append(current_string.decode("ascii"))
                        except UnicodeDecodeError:
                            current_string = bytearray()
                            continue
                    current_string = bytearray()

            if len(current_string) >= 4:
                try:
                    strings.append(current_string.decode("ascii"))
                except UnicodeDecodeError:
                    current_string = bytearray()

        return strings

    def _is_key_format_pattern(self, string: str) -> bool:
        patterns = [
            r"^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$",
            r"^[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}$",
            r"^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$",
        ]

        import re

        return any(re.match(pattern, string) for pattern in patterns)

    def _classify_format(self, string: str) -> str:
        if "-" in string:
            parts = string.split("-")
            lengths = [len(p) for p in parts]

            if lengths == [5, 5, 5, 5, 5]:
                return "microsoft_style"
            elif lengths == [4, 4, 4, 4]:
                return "standard_grouped"
            elif lengths == [8, 4, 4, 4, 12]:
                return "uuid_style"

        return "custom"

    def _analyze_constants(self):
        constants = self._extract_constants()

        checksum_polynomials = {
            0x04C11DB7: ("CRC32", 0.9),
            0xEDB88320: ("CRC32_reversed", 0.9),
            0x1021: ("CRC16_CCITT", 0.85),
            0x8005: ("CRC16_IBM", 0.85),
            0x1EDC6F41: ("CRC32C", 0.85),
        }

        for constant in constants:
            if constant in checksum_polynomials:
                algo_name, confidence = checksum_polynomials[constant]
                self.constraints.append(
                    KeyConstraint(
                        constraint_type="algorithm",
                        description=f"Checksum polynomial: {algo_name}",
                        value=algo_name,
                        confidence=confidence,
                    )
                )

    def _extract_constants(self) -> Set[int]:
        constants = set()
        text_section = self._get_text_section()

        if not text_section:
            return constants

        code = bytes(text_section.content)
        base_address = text_section.virtual_address

        for instr in self.disassembler.disasm(code, base_address):
            if instr.mnemonic in {"mov", "xor", "add", "cmp"}:
                for operand in instr.operands:
                    if operand.type == capstone.CS_OP_IMM:
                        value = operand.imm
                        if 0x100 <= value <= 0xFFFFFFFF:
                            constants.add(value)

        return constants

    def _analyze_comparison_operations(self):
        for routine in self.validation_routines:
            for addr, mnemonic, operands in routine.instructions:
                if mnemonic in {"cmp", "test"}:
                    parts = operands.split(",")
                    if len(parts) == 2:
                        try:
                            value = int(parts[1].strip(), 0)
                            if value not in {0, 1, -1}:
                                self.constraints.append(
                                    KeyConstraint(
                                        constraint_type="validation_value",
                                        description=f"Comparison value: {value}",
                                        value=value,
                                        confidence=0.6,
                                        source_address=addr,
                                    )
                                )
                        except (ValueError, IndexError):
                            continue

    def _analyze_mathematical_operations(self):
        for routine in self.validation_routines:
            mul_operations = []
            div_operations = []

            for addr, mnemonic, operands in routine.instructions:
                if mnemonic in {"mul", "imul"}:
                    mul_operations.append((addr, operands))
                elif mnemonic in {"div", "idiv"}:
                    div_operations.append((addr, operands))

            if len(mul_operations) > 3:
                self.constraints.append(
                    KeyConstraint(
                        constraint_type="algorithm",
                        description="Multiplicative hash function detected",
                        value="multiplicative_hash",
                        confidence=0.7,
                        source_address=routine.address,
                    )
                )

            if len(div_operations) > 2:
                self.constraints.append(
                    KeyConstraint(
                        constraint_type="algorithm",
                        description="Modular arithmetic detected",
                        value="modular",
                        confidence=0.65,
                        source_address=routine.address,
                    )
                )

    def _detect_checksum_algorithms(self):
        imports = self._get_imports()

        crypto_imports = {
            "CryptHashData": ("md5_or_sha", 0.85),
            "CryptCreateHash": ("windows_crypto", 0.8),
            "MD5Init": ("md5", 0.95),
            "SHA1Init": ("sha1", 0.95),
            "SHA256Init": ("sha256", 0.95),
        }

        for import_name in imports:
            if import_name in crypto_imports:
                algo_name, confidence = crypto_imports[import_name]
                self.constraints.append(
                    KeyConstraint(
                        constraint_type="algorithm",
                        description=f"Cryptographic function: {import_name}",
                        value=algo_name,
                        confidence=confidence,
                    )
                )

    def _get_imports(self) -> List[str]:
        imports = []
        if hasattr(self.binary, "imports"):
            for imported_lib in self.binary.imports:
                for entry in imported_lib.entries:
                    if entry.name:
                        imports.append(entry.name)
        return imports

    def _analyze_format_patterns(self):
        for routine in self.validation_routines:
            separator_chars = {"-", " ", "_"}
            separator_found = None

            for _, _, operands in routine.instructions:
                for sep_char in separator_chars:
                    if f"0x{ord(sep_char):x}" in operands.lower():
                        separator_found = sep_char
                        break

            if separator_found:
                self.constraints.append(
                    KeyConstraint(
                        constraint_type="separator",
                        description=f"Group separator: '{separator_found}'",
                        value=separator_found,
                        confidence=0.8,
                        source_address=routine.address,
                    )
                )


class ValidationAnalyzer:

    def __init__(self, binary_path: Path):
        self.binary_path = Path(binary_path)
        self.extractor = ConstraintExtractor(binary_path)
        self.algorithms: List[ExtractedAlgorithm] = []

    def analyze_validation_algorithms(self) -> List[ExtractedAlgorithm]:
        constraints = self.extractor.extract_constraints()

        algorithm_types = self._group_constraints_by_algorithm(constraints)

        for algo_type, algo_constraints in algorithm_types.items():
            algorithm = self._build_algorithm(algo_type, algo_constraints)
            if algorithm:
                self.algorithms.append(algorithm)

        if not self.algorithms:
            self.algorithms.append(self._create_generic_algorithm(constraints))

        return self.algorithms

    def _group_constraints_by_algorithm(
        self, constraints: List[KeyConstraint]
    ) -> Dict[str, List[KeyConstraint]]:
        groups = {}

        for constraint in constraints:
            if constraint.constraint_type == "algorithm":
                algo_name = constraint.value
                if algo_name not in groups:
                    groups[algo_name] = []
                groups[algo_name].append(constraint)

        if "generic" not in groups:
            groups["generic"] = [
                c for c in constraints if c.constraint_type != "algorithm"
            ]

        return groups

    def _build_algorithm(
        self, algo_type: str, constraints: List[KeyConstraint]
    ) -> Optional[ExtractedAlgorithm]:
        if algo_type == "crc":
            return self._build_crc_algorithm(constraints)
        elif algo_type in {"md5", "sha1", "sha256"}:
            return self._build_hash_algorithm(algo_type, constraints)
        elif algo_type == "multiplicative_hash":
            return self._build_multiplicative_algorithm(constraints)
        elif algo_type == "modular":
            return self._build_modular_algorithm(constraints)
        else:
            return self._build_generic_algorithm(constraints)

    def _build_crc_algorithm(
        self, constraints: List[KeyConstraint]
    ) -> ExtractedAlgorithm:
        polynomial = 0xEDB88320

        for constraint in constraints:
            if "CRC32" in str(constraint.value):
                if "reversed" in str(constraint.value):
                    polynomial = 0xEDB88320
                else:
                    polynomial = 0x04C11DB7

        def crc32_validate(key: str) -> int:
            return zlib.crc32(key.encode()) & 0xFFFFFFFF

        return ExtractedAlgorithm(
            algorithm_name="CRC32",
            parameters={"polynomial": polynomial},
            validation_function=crc32_validate,
            key_format=SerialFormat.ALPHANUMERIC,
            constraints=constraints,
            confidence=0.85,
        )

    def _build_hash_algorithm(
        self, algo_type: str, constraints: List[KeyConstraint]
    ) -> ExtractedAlgorithm:
        hash_functions = {
            "md5": hashlib.md5,
            "sha1": hashlib.sha1,
            "sha256": hashlib.sha256,
        }

        hash_func = hash_functions.get(algo_type, hashlib.sha256)

        def hash_validate(key: str) -> str:
            return hash_func(key.encode()).hexdigest()

        return ExtractedAlgorithm(
            algorithm_name=algo_type.upper(),
            parameters={"hash_function": algo_type},
            validation_function=hash_validate,
            key_format=SerialFormat.HEXADECIMAL,
            constraints=constraints,
            confidence=0.9,
        )

    def _build_multiplicative_algorithm(
        self, constraints: List[KeyConstraint]
    ) -> ExtractedAlgorithm:
        def multiplicative_validate(key: str) -> int:
            result = 0
            multiplier = 31
            for char in key:
                result = result * multiplier + ord(char)
            return result & 0xFFFFFFFF

        return ExtractedAlgorithm(
            algorithm_name="Multiplicative Hash",
            parameters={"multiplier": 31},
            validation_function=multiplicative_validate,
            key_format=SerialFormat.ALPHANUMERIC,
            constraints=constraints,
            confidence=0.75,
        )

    def _build_modular_algorithm(
        self, constraints: List[KeyConstraint]
    ) -> ExtractedAlgorithm:
        modulus = 97

        def modular_validate(key: str) -> int:
            numeric = "".join(
                c if c.isdigit() else str(ord(c) - ord("A") + 10) for c in key
            )
            return int(numeric) % modulus

        return ExtractedAlgorithm(
            algorithm_name="Modular Arithmetic",
            parameters={"modulus": modulus},
            validation_function=modular_validate,
            key_format=SerialFormat.ALPHANUMERIC,
            constraints=constraints,
            confidence=0.7,
        )

    def _build_generic_algorithm(
        self, constraints: List[KeyConstraint]
    ) -> ExtractedAlgorithm:
        return ExtractedAlgorithm(
            algorithm_name="Generic",
            parameters={},
            validation_function=None,
            key_format=SerialFormat.ALPHANUMERIC,
            constraints=constraints,
            confidence=0.5,
        )

    def _create_generic_algorithm(
        self, constraints: List[KeyConstraint]
    ) -> ExtractedAlgorithm:
        return self._build_generic_algorithm(constraints)


class KeySynthesizer:

    def __init__(self):
        self.generator = SerialNumberGenerator()
        self.solver = z3.Solver()

    def synthesize_key(
        self,
        algorithm: ExtractedAlgorithm,
        target_data: Optional[Dict[str, Any]] = None,
    ) -> GeneratedSerial:
        if algorithm.validation_function:
            return self._synthesize_with_validation(algorithm, target_data)
        else:
            return self._synthesize_from_constraints(algorithm, target_data)

    def _synthesize_with_validation(
        self,
        algorithm: ExtractedAlgorithm,
        target_data: Optional[Dict[str, Any]] = None,
    ) -> GeneratedSerial:
        constraints = self._build_serial_constraints(algorithm)

        if target_data:
            base_seed = hashlib.sha256(
                str(target_data).encode()
            ).hexdigest()[:16]
            seed_value = int(base_seed, 16)
        else:
            seed_value = 0

        max_attempts = 10000
        for attempt in range(max_attempts):
            deterministic_seed = seed_value + attempt
            candidate = self.generator.generate_serial(constraints, seed=deterministic_seed)

            try:
                if algorithm.validation_function(candidate.serial):
                    candidate.confidence = algorithm.confidence
                    candidate.algorithm = algorithm.algorithm_name
                    return candidate
            except Exception:
                continue

        return self.generator.generate_serial(constraints)

    def _synthesize_from_constraints(
        self,
        algorithm: ExtractedAlgorithm,
        target_data: Optional[Dict[str, Any]] = None,
    ) -> GeneratedSerial:
        constraints = self._build_serial_constraints(algorithm)

        seed = None
        if target_data:
            seed = target_data

        return self.generator.generate_serial(constraints, seed=seed)

    def _build_serial_constraints(
        self, algorithm: ExtractedAlgorithm
    ) -> SerialConstraints:
        length = 16
        format_type = algorithm.key_format or SerialFormat.ALPHANUMERIC
        groups = 1
        separator = "-"
        checksum_algo = None

        for constraint in algorithm.constraints:
            if constraint.constraint_type == "length":
                length = constraint.value
            elif constraint.constraint_type == "format":
                if "microsoft" in str(constraint.value).lower():
                    format_type = SerialFormat.MICROSOFT
                    length = 25
                    groups = 5
            elif constraint.constraint_type == "separator":
                separator = constraint.value
            elif constraint.constraint_type == "checksum":
                checksum_algo = constraint.value

        return SerialConstraints(
            length=length,
            format=format_type,
            groups=groups,
            group_separator=separator,
            checksum_algorithm=checksum_algo,
        )

    def synthesize_batch(
        self,
        algorithm: ExtractedAlgorithm,
        count: int,
        unique: bool = True,
    ) -> List[GeneratedSerial]:
        keys = []
        generated_set = set()

        for i in range(count):
            target_data = {"index": i} if unique else None

            max_retries = 10
            for retry in range(max_retries):
                key = self.synthesize_key(algorithm, target_data)

                if not unique or key.serial not in generated_set:
                    keys.append(key)
                    generated_set.add(key.serial)
                    break

                target_data = {"index": i, "retry": retry}

        return keys

    def synthesize_for_user(
        self,
        algorithm: ExtractedAlgorithm,
        username: str,
        email: Optional[str] = None,
        hardware_id: Optional[str] = None,
    ) -> GeneratedSerial:
        user_data = {"username": username}
        if email:
            user_data["email"] = email
        if hardware_id:
            user_data["hardware_id"] = hardware_id

        key = self.synthesize_key(algorithm, user_data)
        key.hardware_id = hardware_id

        return key

    def synthesize_with_z3(
        self, constraints: List[KeyConstraint]
    ) -> Optional[str]:
        self.solver.reset()

        key_length = 16
        for constraint in constraints:
            if constraint.constraint_type == "length":
                key_length = constraint.value
                break

        key_vars = [z3.BitVec(f"k{i}", 8) for i in range(key_length)]

        for constraint in constraints:
            if constraint.constraint_type == "charset":
                charset_type = constraint.value
                if charset_type == "numeric":
                    for var in key_vars:
                        self.solver.add(z3.And(var >= ord("0"), var <= ord("9")))
                elif charset_type == "uppercase":
                    for var in key_vars:
                        self.solver.add(z3.And(var >= ord("A"), var <= ord("Z")))
                elif charset_type == "alphanumeric":
                    for var in key_vars:
                        self.solver.add(
                            z3.Or(
                                z3.And(var >= ord("0"), var <= ord("9")),
                                z3.And(var >= ord("A"), var <= ord("Z")),
                            )
                        )

        if self.solver.check() == z3.sat:
            model = self.solver.model()
            key_chars = []

            for var in key_vars:
                value = model.eval(var)
                if value is not None:
                    key_chars.append(chr(value.as_long()))
                else:
                    key_chars.append("A")

            return "".join(key_chars)

        return None


class LicenseKeygen:

    def __init__(self, binary_path: Optional[Path] = None):
        self.binary_path = Path(binary_path) if binary_path else None
        self.extractor = (
            ConstraintExtractor(self.binary_path) if self.binary_path else None
        )
        self.analyzer = (
            ValidationAnalyzer(self.binary_path) if self.binary_path else None
        )
        self.synthesizer = KeySynthesizer()
        self.generator = SerialNumberGenerator()

    def crack_license_from_binary(
        self, count: int = 1
    ) -> List[GeneratedSerial]:
        if not self.analyzer:
            raise ValueError("Binary path required for analysis")

        algorithms = self.analyzer.analyze_validation_algorithms()

        if not algorithms:
            raise ValueError("No validation algorithms detected")

        best_algorithm = max(algorithms, key=lambda a: a.confidence)

        return self.synthesizer.synthesize_batch(
            best_algorithm, count, unique=True
        )

    def generate_key_from_algorithm(
        self,
        algorithm_name: str,
        **kwargs: Any,
    ) -> GeneratedSerial:
        if algorithm_name == "microsoft":
            constraints = SerialConstraints(
                length=25,
                format=SerialFormat.MICROSOFT,
                groups=5,
            )
        elif algorithm_name == "uuid":
            constraints = SerialConstraints(
                length=36,
                format=SerialFormat.UUID,
            )
        elif algorithm_name == "luhn":
            return GeneratedSerial(
                serial=self.generator._generate_luhn_serial(
                    kwargs.get("length", 16)
                ),
                algorithm="luhn",
                confidence=0.9,
            )
        elif algorithm_name == "crc32":
            return GeneratedSerial(
                serial=self.generator._generate_crc32_serial(
                    kwargs.get("length", 16)
                ),
                algorithm="crc32",
                confidence=0.85,
            )
        else:
            constraints = SerialConstraints(
                length=kwargs.get("length", 16),
                format=SerialFormat.ALPHANUMERIC,
                groups=kwargs.get("groups", 4),
            )

        return self.generator.generate_serial(constraints)

    def generate_volume_license(
        self,
        product_id: str,
        count: int = 100,
    ) -> List[GeneratedSerial]:
        from cryptography.hazmat.primitives.asymmetric import rsa

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        licenses = []
        for i in range(count):
            license_key = self.generator.generate_rsa_signed(
                private_key,
                product_id,
                f"Volume-{i:04d}",
                features=["enterprise", "unlimited", "support"],
            )
            licenses.append(license_key)

        return licenses

    def generate_hardware_locked_key(
        self,
        hardware_id: str,
        product_id: str,
    ) -> GeneratedSerial:
        combined_data = f"{product_id}:{hardware_id}".encode()
        hash_result = hashlib.sha256(combined_data).hexdigest()

        key_base = hash_result[:20].upper()
        formatted = "-".join(key_base[i : i + 5] for i in range(0, 20, 5))

        checksum = self.generator._calculate_crc16(formatted)
        final_key = f"{formatted}-{checksum}"

        return GeneratedSerial(
            serial=final_key,
            hardware_id=hardware_id,
            algorithm="hardware_locked",
            confidence=0.95,
        )

    def generate_time_limited_key(
        self,
        product_id: str,
        days_valid: int = 30,
    ) -> GeneratedSerial:
        import secrets

        secret_key = secrets.token_bytes(32)

        return self.generator.generate_time_based(
            secret_key,
            validity_days=days_valid,
            product_id=product_id,
        )

    def generate_feature_key(
        self,
        base_product: str,
        features: List[str],
    ) -> GeneratedSerial:
        base_serial = self.generate_key_from_algorithm(
            "alphanumeric", length=16, groups=4
        ).serial

        return self.generator.generate_feature_encoded(
            base_serial,
            features,
        )

    def brute_force_key(
        self,
        partial_key: str,
        missing_positions: List[int],
        validation_func: Callable[[str], bool],
        charset: str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
    ) -> Optional[str]:
        import itertools

        key_list = list(partial_key)
        max_combinations = len(charset) ** len(missing_positions)

        if max_combinations > 1000000:
            return None

        for combination in itertools.product(charset, repeat=len(missing_positions)):
            for i, pos in enumerate(missing_positions):
                key_list[pos] = combination[i]

            candidate = "".join(key_list)

            if validation_func(candidate):
                return candidate

        return None

    def reverse_engineer_keygen(
        self,
        valid_keys: List[str],
        invalid_keys: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        return self.generator.reverse_engineer_algorithm(
            valid_keys,
            invalid_keys,
        )
