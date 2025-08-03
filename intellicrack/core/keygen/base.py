
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

class ParamType(Enum):
    STRING = "string"
    INTEGER = "integer"
    BOOLEAN = "boolean"
    HEX = "hex"
    BASE64 = "base64"
    FILE = "file"
    CHOICE = "choice"

@dataclass
class KeygenParameter:
    """Defines a parameter required by a keygen template."""
    name: str
    param_type: ParamType
    description: str
    required: bool = True
    default: Optional[Any] = None
    choices: Optional[List[str]] = None

@dataclass
class KeygenResult:
    """Represents the result of a key generation operation."""
    success: bool
    keys: List[str] = field(default_factory=list)
    error: Optional[str] = None
    log: List[str] = field(default_factory=list)

class KeygenTemplate(ABC):
    """Abstract base class for all keygen templates."""

    @property
    @abstractmethod
    def name(self) -> str:
        """The display name of the keygen template."""
        # This property will be implemented by concrete subclasses.
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """A brief description of what this keygen does."""
        # This property will be implemented by concrete subclasses.
        pass

    @abstractmethod
    def get_parameters(self) -> List[KeygenParameter]:
        """Returns a list of parameters required for this keygen."""
        # This method will be implemented by concrete subclasses.
        pass

    @abstractmethod
    def generate(self, params: Dict[str, Any]) -> KeygenResult:
        """Generates the license key(s) based on the provided parameters."""
        # This method will be implemented by concrete subclasses.
        pass
