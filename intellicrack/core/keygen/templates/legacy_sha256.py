
import base64
import hashlib
import time
from typing import Any, Dict, List

from ..base import KeygenTemplate, KeygenParameter, ParamType, KeygenResult

class LegacySHA256Keygen(KeygenTemplate):
    """Replicates the original SHA256-based key generation logic."""

    @property
    def name(self) -> str:
        return "Legacy SHA256 Keygen"

    @property
    def description(self) -> str:
        return "Generates a key using SHA256, suitable for simple license checks."

    def get_parameters(self) -> List[KeygenParameter]:
        return [
            KeygenParameter(
                name="name",
                param_type=ParamType.STRING,
                description="The user or company name for the license.",
                required=True
            ),
            KeygenParameter(
                name="version",
                param_type=ParamType.STRING,
                description="The software version for the license.",
                required=True
            ),
            KeygenParameter(
                name="seed",
                param_type=ParamType.STRING,
                description="An optional seed for deterministic key generation. If omitted, a timestamp is used.",
                required=False
            ),
            KeygenParameter(
                name="key_format",
                param_type=ParamType.CHOICE,
                description="The output format of the generated key.",
                required=True,
                default="####-####-####-####",
                choices=["####-####-####-####", "#####-#####-#####", "###-#######-###", "XXX-XXX-XXX-XXX-XXX"]
            )
        ]

    def generate(self, params: Dict[str, Any]) -> KeygenResult:
        name = params.get("name")
        version = params.get("version")
        seed = params.get("seed")
        key_format = params.get("key_format")

        if not name or not version or not key_format:
            return KeygenResult(success=False, error="Missing required parameters.")

        log = []

        if seed:
            raw = f"{name}-{version}-{seed}"
            log.append(f"Using provided seed: {seed}")
        else:
            timestamp = str(int(time.time()))
            raw = f"{name}-{version}-{timestamp}"
            log.append(f"Using timestamp as seed: {timestamp}")

        log.append(f"Raw key data: {raw}")

        digest = hashlib.sha256(raw.encode()).digest()
        log.append(f"SHA256 Digest (hex): {digest.hex()}")

        key_base = base64.urlsafe_b64encode(digest[:16]).decode().rstrip("=")
        log.append(f"Base64 encoded key base: {key_base}")

        try:
            if key_format == "####-####-####-####":
                formatted_key = "-".join([key_base[i:i + 4] for i in range(0, 16, 4)])
            elif key_format == "#####-#####-#####":
                formatted_key = "-".join([key_base[i:i + 5] for i in range(0, 15, 5)])
            elif key_format == "###-#######-###":
                formatted_key = f"{key_base[:3]}-{key_base[3:10]}-{key_base[10:13]}"
            elif key_format == "XXX-XXX-XXX-XXX-XXX":
                formatted_key = "-".join([key_base[i:i + 3] for i in range(0, 15, 3)])
            else:
                return KeygenResult(success=False, error=f"Invalid key format: {key_format}")
        except IndexError:
            return KeygenResult(success=False, error="Could not generate key with the selected format. The base key is too short.")

        log.append(f"Formatted key: {formatted_key}")

        return KeygenResult(success=True, keys=[formatted_key], log=log)
