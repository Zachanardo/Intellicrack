"""Certificate caching for efficient MITM certificate generation."""

import hashlib
import json
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from intellicrack.core.certificate.cert_chain_generator import CertificateChain


class CertificateCache:
    """Thread-safe LRU cache for generated certificate chains."""

    def __init__(self, cache_dir: Optional[Path] = None, max_entries: int = 1000):
        """Initialize certificate cache.

        Args:
            cache_dir: Directory to store cached certificates
                      (defaults to ~/.intellicrack/cert_cache/)
            max_entries: Maximum number of cached certificates before LRU eviction

        """
        if cache_dir is None:
            cache_dir = Path.home() / ".intellicrack" / "cert_cache"

        self.cache_dir = cache_dir
        self.max_entries = max_entries
        self.metadata_file = self.cache_dir / "cache_metadata.json"
        self.lock = threading.Lock()

        self._initialize_cache()

    def _initialize_cache(self) -> None:
        """Create cache directory and metadata file if they don't exist."""
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        if not self.metadata_file.exists():
            self._save_metadata({})

    def _load_metadata(self) -> Dict:
        """Load cache metadata from disk.

        Returns:
            Dictionary containing cache metadata

        """
        try:
            with open(self.metadata_file, "r") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def _save_metadata(self, metadata: Dict) -> None:
        """Save cache metadata to disk.

        Args:
            metadata: Dictionary containing cache metadata

        """
        with open(self.metadata_file, "w") as f:
            json.dump(metadata, f, indent=2)

    def _domain_hash(self, domain: str) -> str:
        """Generate hash for domain name.

        Args:
            domain: Domain name to hash

        Returns:
            SHA256 hash of domain

        """
        return hashlib.sha256(domain.encode()).hexdigest()

    def _get_domain_dir(self, domain: str) -> Path:
        """Get cache directory for domain.

        Args:
            domain: Domain name

        Returns:
            Path to domain's cache directory

        """
        return self.cache_dir / self._domain_hash(domain)

    def get_cached_cert(self, domain: str) -> Optional[CertificateChain]:
        """Retrieve cached certificate chain for domain.

        Args:
            domain: Domain name to lookup

        Returns:
            CertificateChain if cached and valid, None otherwise

        """
        with self.lock:
            metadata = self._load_metadata()
            domain_hash = self._domain_hash(domain)

            if domain_hash not in metadata:
                return None

            entry = metadata[domain_hash]

            expiration = datetime.fromisoformat(entry["expiration"])
            if datetime.now() >= expiration:
                return None

            domain_dir = self._get_domain_dir(domain)

            try:
                leaf_cert = self._load_cert(domain_dir / "leaf.pem")
                intermediate_cert = self._load_cert(domain_dir / "intermediate.pem")
                root_cert = self._load_cert(domain_dir / "root.pem")
                leaf_key = self._load_private_key(domain_dir / "leaf_key.pem")
                intermediate_key = self._load_private_key(domain_dir / "intermediate_key.pem")
                root_key = self._load_private_key(domain_dir / "root_key.pem")

                entry["last_accessed"] = datetime.now().isoformat()
                self._save_metadata(metadata)

                return CertificateChain(
                    leaf_cert=leaf_cert,
                    intermediate_cert=intermediate_cert,
                    root_cert=root_cert,
                    leaf_key=leaf_key,
                    intermediate_key=intermediate_key,
                    root_key=root_key,
                )

            except Exception:
                del metadata[domain_hash]
                self._save_metadata(metadata)
                return None

    def store_cert(self, domain: str, chain: CertificateChain) -> bool:
        """Store certificate chain in cache.

        Args:
            domain: Domain name
            chain: Certificate chain to cache

        Returns:
            True if successfully stored

        """
        with self.lock:
            self._evict_if_needed()

            domain_dir = self._get_domain_dir(domain)
            domain_dir.mkdir(parents=True, exist_ok=True)

            try:
                self._save_cert(chain.leaf_cert, domain_dir / "leaf.pem")
                self._save_cert(chain.intermediate_cert, domain_dir / "intermediate.pem")
                self._save_cert(chain.root_cert, domain_dir / "root.pem")
                self._save_private_key(chain.leaf_key, domain_dir / "leaf_key.pem")
                self._save_private_key(chain.intermediate_key, domain_dir / "intermediate_key.pem")
                self._save_private_key(chain.root_key, domain_dir / "root_key.pem")

                metadata = self._load_metadata()
                domain_hash = self._domain_hash(domain)

                metadata[domain_hash] = {
                    "domain": domain,
                    "created": datetime.now().isoformat(),
                    "last_accessed": datetime.now().isoformat(),
                    "expiration": chain.leaf_cert.not_valid_after_utc.isoformat(),
                }

                self._save_metadata(metadata)
                return True

            except Exception:
                return False

    def _evict_if_needed(self) -> None:
        """Evict least recently used entries if cache exceeds max size."""
        metadata = self._load_metadata()

        if len(metadata) < self.max_entries:
            return

        sorted_entries = sorted(
            metadata.items(),
            key=lambda x: x[1].get("last_accessed", ""),
        )

        num_to_evict = len(metadata) - self.max_entries + 1

        for domain_hash, _entry in sorted_entries[:num_to_evict]:
            domain_dir = self.cache_dir / domain_hash
            try:
                import shutil
                shutil.rmtree(domain_dir, ignore_errors=True)
            except Exception as e:
                import logging
                logging.getLogger(__name__).debug(f"Failed to evict cache entry: {e}")

            del metadata[domain_hash]

        self._save_metadata(metadata)

    def clear_cache(self) -> bool:
        """Delete all cached certificates.

        Returns:
            True if successful

        """
        with self.lock:
            try:
                import shutil
                for item in self.cache_dir.iterdir():
                    if item.is_dir():
                        shutil.rmtree(item)

                self._save_metadata({})
                return True

            except Exception:
                return False

    def get_cache_stats(self) -> Dict:
        """Get cache statistics.

        Returns:
            Dictionary with cache statistics

        """
        with self.lock:
            metadata = self._load_metadata()

            total_entries = len(metadata)
            expired_count = 0
            now = datetime.now()

            for entry in metadata.values():
                expiration = datetime.fromisoformat(entry["expiration"])
                if now >= expiration:
                    expired_count += 1

            return {
                "total_entries": total_entries,
                "expired_entries": expired_count,
                "valid_entries": total_entries - expired_count,
                "max_entries": self.max_entries,
                "utilization_percent": (total_entries / self.max_entries * 100)
                if self.max_entries > 0
                else 0,
            }

    def remove_expired(self) -> int:
        """Remove expired certificates from cache.

        Returns:
            Number of entries removed

        """
        with self.lock:
            metadata = self._load_metadata()
            now = datetime.now()
            removed_count = 0

            to_remove = []
            for domain_hash, entry in metadata.items():
                expiration = datetime.fromisoformat(entry["expiration"])
                if now >= expiration:
                    to_remove.append(domain_hash)

            for domain_hash in to_remove:
                domain_dir = self.cache_dir / domain_hash
                try:
                    import shutil
                    shutil.rmtree(domain_dir, ignore_errors=True)
                    del metadata[domain_hash]
                    removed_count += 1
                except Exception as e:
                    import logging
                    logging.getLogger(__name__).debug(f"Failed to remove expired entry: {e}")

            if removed_count > 0:
                self._save_metadata(metadata)

            return removed_count

    def _load_cert(self, cert_path: Path) -> x509.Certificate:
        """Load certificate from PEM file.

        Args:
            cert_path: Path to certificate file

        Returns:
            Loaded certificate

        """
        with open(cert_path, "rb") as f:
            return x509.load_pem_x509_certificate(f.read())

    def _save_cert(self, cert: x509.Certificate, cert_path: Path) -> None:
        """Save certificate to PEM file.

        Args:
            cert: Certificate to save
            cert_path: Path to save certificate

        """
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

    def _load_private_key(self, key_path: Path) -> rsa.RSAPrivateKey:
        """Load private key from PEM file.

        Args:
            key_path: Path to key file

        Returns:
            Loaded private key

        """
        with open(key_path, "rb") as f:
            return serialization.load_pem_private_key(
                f.read(),
                password=None,
            )

    def _save_private_key(self, key: rsa.RSAPrivateKey, key_path: Path) -> None:
        """Save private key to PEM file.

        Args:
            key: Private key to save
            key_path: Path to save key

        """
        with open(key_path, "wb") as f:
            f.write(
                key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
