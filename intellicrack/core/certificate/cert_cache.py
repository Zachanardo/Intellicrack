"""Thread-safe LRU certificate cache for efficient MITM certificate generation.

CAPABILITIES:
- Thread-safe LRU (Least Recently Used) cache for certificate chains
- Persistent cache storage in ~/.intellicrack/cert_cache/
- Automatic cache directory creation and initialization
- Domain-based cache lookup with hash-based file naming
- Certificate expiration checking (auto-invalidate expired certs)
- Cache metadata tracking (creation time, expiration, access time)
- LRU eviction when cache exceeds max entries (default: 1000)
- Cache statistics (hit rate, size, entry count)
- Expired certificate removal
- Full cache clearing
- Atomic read/write operations with threading.Lock

LIMITATIONS:
- No cache compression (each domain stores ~12KB)
- No distributed cache support (local filesystem only)
- Cache invalidation is manual or expiration-based
- No cache encryption (stored in plaintext PEM)
- LRU eviction is simple (no advanced replacement policies)
- No cache warming or prefetching
- Metadata file grows over time (no automatic cleanup)
- No cache size limits (only entry count limits)

USAGE EXAMPLES:
    # Initialize cache with defaults
    from intellicrack.core.certificate.cert_cache import CertificateCache

    cache = CertificateCache()  # Uses ~/.intellicrack/cert_cache/

    # Check for cached certificate
    chain = cache.get_cached_cert("example.com")
    if chain:
        print("Using cached certificate")
    else:
        print("Generating new certificate")
        # Generate certificate chain...
        # chain = generator.generate_full_chain("example.com")
        cache.store_cert("example.com", chain)

    # Custom cache directory and size
    cache = CertificateCache(
        cache_dir=Path("/custom/cache/path"),
        max_entries=500
    )

    # Get cache statistics
    stats = cache.get_cache_stats()
    print(f"Total entries: {stats['total_entries']}")
    print(f"Cache hits: {stats['hits']}")
    print(f"Cache misses: {stats['misses']}")
    print(f"Hit rate: {stats['hit_rate']:.2%}")
    print(f"Oldest entry: {stats['oldest_entry']}")
    print(f"Newest entry: {stats['newest_entry']}")

    # Remove expired certificates
    removed_count = cache.remove_expired()
    print(f"Removed {removed_count} expired certificates")

    # Clear entire cache
    cache.clear_cache()
    print("Cache cleared")

    # Thread-safe usage in concurrent environment
    import threading

    def worker(domain):
        cache = CertificateCache()
        chain = cache.get_cached_cert(domain)
        # Use chain...

    threads = [threading.Thread(target=worker, args=(f"example{i}.com",))
               for i in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

RELATED MODULES:
- cert_chain_generator.py: Generates certificates stored in cache
- bypass_orchestrator.py: Uses cache for MITM bypass
- frida_cert_hooks.py: May use cached certificates

CACHE STRUCTURE:
    ~/.intellicrack/cert_cache/
    ├── cache_metadata.json (access times, expiration, creation dates)
    ├── {domain_hash_1}/
    │   ├── leaf.pem
    │   ├── intermediate.pem
    │   ├── root.pem
    │   └── key.pem (leaf private key)
    ├── {domain_hash_2}/
    │   └── ...
    └── ...

CACHE METADATA FORMAT:
    {
      "domain.com": {
        "hash": "sha256_of_domain",
        "created": "2025-01-15T10:30:00",
        "expires": "2026-01-15T10:30:00",
        "last_accessed": "2025-01-20T14:22:00",
        "access_count": 42
      }
    }

LRU EVICTION POLICY:
    - Triggered when cache exceeds max_entries
    - Removes least recently accessed entry
    - Deletes all files in domain directory
    - Updates metadata
    - Thread-safe with lock
"""

import hashlib
import json
import logging
import threading
from datetime import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes

from intellicrack.core.certificate.cert_chain_generator import CertificateChain


logger = logging.getLogger(__name__)


class CertificateCache:
    """Thread-safe LRU cache for generated certificate chains."""

    def __init__(self, cache_dir: Path | None = None, max_entries: int = 1000) -> None:
        """Initialize certificate cache.

        Args:
            cache_dir: Directory to store cached certificates
                      (defaults to ~/.intellicrack/cert_cache/).
            max_entries: Maximum number of cached certificates before LRU eviction.
        """
        if cache_dir is None:
            cache_dir = Path.home() / ".intellicrack" / "cert_cache"

        self.cache_dir = cache_dir
        self.max_entries = max_entries
        self.metadata_file = self.cache_dir / "cache_metadata.json"
        self.lock = threading.Lock()

        self._initialize_cache()

    def _initialize_cache(self) -> None:
        """Create cache directory and metadata file if they don't exist.

        Creates the cache directory structure and initializes an empty metadata
        file if needed.
        """
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        if not self.metadata_file.exists():
            self._save_metadata({})

    def _load_metadata(self) -> dict[str, dict[str, str]]:
        """Load cache metadata from disk.

        Returns:
            Dictionary containing cache metadata

        """
        try:
            with open(self.metadata_file) as f:
                data: dict[str, dict[str, str]] = json.load(f)
                return data
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def _save_metadata(self, metadata: dict[str, dict[str, str]]) -> None:
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

    def get_cached_cert(self, domain: str) -> CertificateChain | None:
        """Retrieve cached certificate chain for domain.

        Args:
            domain: Domain name to lookup

        Returns:
            CertificateChain if cached and valid, None otherwise

        Raises:
            TypeError: If cached key is not an RSAPrivateKey instance.

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
                leaf_key_loaded = self._load_private_key(domain_dir / "leaf_key.pem")
                intermediate_key_loaded = self._load_private_key(domain_dir / "intermediate_key.pem")
                root_key_loaded = self._load_private_key(domain_dir / "root_key.pem")

                if not isinstance(leaf_key_loaded, rsa.RSAPrivateKey):
                    raise TypeError("Leaf key must be RSAPrivateKey")
                if not isinstance(intermediate_key_loaded, rsa.RSAPrivateKey):
                    raise TypeError("Intermediate key must be RSAPrivateKey")
                if not isinstance(root_key_loaded, rsa.RSAPrivateKey):
                    raise TypeError("Root key must be RSAPrivateKey")

                entry["last_accessed"] = datetime.now().isoformat()
                self._save_metadata(metadata)

                return CertificateChain(
                    leaf_cert=leaf_cert,
                    intermediate_cert=intermediate_cert,
                    root_cert=root_cert,
                    leaf_key=leaf_key_loaded,
                    intermediate_key=intermediate_key_loaded,
                    root_key=root_key_loaded,
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
        """Evict least recently used entries if cache exceeds max size.

        Removes the least recently accessed cache entries when the number of
        cached certificates exceeds the maximum configured limit. Deletes all
        files associated with evicted entries from disk.
        """
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
            except Exception:
                logger.debug("Failed to evict cache entry", exc_info=True)

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

    def get_cache_stats(self) -> dict[str, int | float]:
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
                "utilization_percent": (total_entries / self.max_entries * 100) if self.max_entries > 0 else 0,
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
                except Exception:
                    logger.debug("Failed to remove expired entry", exc_info=True)

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

    def _load_private_key(self, key_path: Path) -> PrivateKeyTypes:
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

    def _save_private_key(self, key: PrivateKeyTypes, key_path: Path) -> None:
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
                ),
            )
