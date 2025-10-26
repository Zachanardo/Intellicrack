"""Data structures for certificate validation detection reports."""

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import List


class BypassMethod(Enum):
    """Recommended bypass method for certificate validation."""

    BINARY_PATCH = "binary_patch"
    FRIDA_HOOK = "frida_hook"
    HYBRID = "hybrid"
    MITM_PROXY = "mitm_proxy"
    NONE = "none"


@dataclass
class ValidationFunction:
    """Information about a detected certificate validation function."""

    address: int
    api_name: str
    library: str
    confidence: float
    context: str = ""
    references: List[int] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return asdict(self)

    def __str__(self) -> str:
        """Human-readable string representation."""
        return (
            f"ValidationFunction(api={self.api_name}, "
            f"addr=0x{self.address:x}, "
            f"lib={self.library}, "
            f"confidence={self.confidence:.2f})"
        )


@dataclass
class DetectionReport:
    """Complete report of certificate validation detection."""

    binary_path: str
    detected_libraries: List[str]
    validation_functions: List[ValidationFunction]
    recommended_method: BypassMethod
    risk_level: str
    timestamp: datetime = field(default_factory=datetime.now)

    def to_json(self) -> str:
        """Export report as JSON.

        Returns:
            JSON string representation

        """
        data = self.to_dict()
        data["timestamp"] = self.timestamp.isoformat()
        data["recommended_method"] = self.recommended_method.value
        return json.dumps(data, indent=2)

    def to_dict(self) -> dict:
        """Export report as dictionary.

        Returns:
            Dictionary representation

        """
        return {
            "binary_path": self.binary_path,
            "detected_libraries": self.detected_libraries,
            "validation_functions": [
                func.to_dict() for func in self.validation_functions
            ],
            "recommended_method": self.recommended_method.value,
            "risk_level": self.risk_level,
            "timestamp": self.timestamp.isoformat(),
        }

    def to_text(self) -> str:
        """Generate human-readable text report.

        Returns:
            Formatted text report

        """
        lines = [
            "=" * 80,
            "CERTIFICATE VALIDATION DETECTION REPORT",
            "=" * 80,
            f"Binary: {self.binary_path}",
            f"Timestamp: {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}",
            f"Risk Level: {self.risk_level.upper()}",
            f"Recommended Method: {self.recommended_method.value}",
            "",
            "DETECTED TLS LIBRARIES:",
            "-" * 80,
        ]

        if self.detected_libraries:
            for lib in self.detected_libraries:
                lines.append(f"  - {lib}")
        else:
            lines.append("  (none)")

        lines.extend([
            "",
            "DETECTED VALIDATION FUNCTIONS:",
            "-" * 80,
        ])

        if self.validation_functions:
            for func in self.validation_functions:
                lines.extend([
                    f"  API: {func.api_name}",
                    f"  Library: {func.library}",
                    f"  Address: 0x{func.address:08x}",
                    f"  Confidence: {func.confidence:.2%}",
                    f"  Cross-references: {len(func.references)}",
                ])
                if func.context:
                    context_preview = func.context[:200]
                    if len(func.context) > 200:
                        context_preview += "..."
                    lines.append(f"  Context: {context_preview}")
                lines.append("")
        else:
            lines.append("  (none detected)")

        lines.append("=" * 80)
        return "\n".join(lines)

    @classmethod
    def from_dict(cls, data: dict) -> "DetectionReport":
        """Create DetectionReport from dictionary.

        Args:
            data: Dictionary containing report data

        Returns:
            DetectionReport instance

        """
        validation_functions = [
            ValidationFunction(**func_data)
            for func_data in data.get("validation_functions", [])
        ]

        method_str = data.get("recommended_method", "none")
        try:
            recommended_method = BypassMethod(method_str)
        except ValueError:
            recommended_method = BypassMethod.NONE

        timestamp_str = data.get("timestamp")
        if timestamp_str:
            timestamp = datetime.fromisoformat(timestamp_str)
        else:
            timestamp = datetime.now()

        return cls(
            binary_path=data["binary_path"],
            detected_libraries=data.get("detected_libraries", []),
            validation_functions=validation_functions,
            recommended_method=recommended_method,
            risk_level=data.get("risk_level", "unknown"),
            timestamp=timestamp,
        )

    @classmethod
    def from_json(cls, json_str: str) -> "DetectionReport":
        """Create DetectionReport from JSON string.

        Args:
            json_str: JSON string containing report data

        Returns:
            DetectionReport instance

        """
        data = json.loads(json_str)
        return cls.from_dict(data)

    def get_high_confidence_functions(self, threshold: float = 0.7) -> List[ValidationFunction]:
        """Get validation functions with confidence above threshold.

        Args:
            threshold: Minimum confidence score (0.0 to 1.0)

        Returns:
            List of high-confidence validation functions

        """
        return [
            func for func in self.validation_functions
            if func.confidence >= threshold
        ]

    def has_validation(self) -> bool:
        """Check if any certificate validation was detected.

        Returns:
            True if validation functions were detected

        """
        return len(self.validation_functions) > 0

    def get_unique_apis(self) -> List[str]:
        """Get list of unique API names detected.

        Returns:
            List of unique API names

        """
        return list(set(func.api_name for func in self.validation_functions))

    def get_unique_libraries(self) -> List[str]:
        """Get list of unique libraries containing validation functions.

        Returns:
            List of unique library names

        """
        return list(set(func.library for func in self.validation_functions))
