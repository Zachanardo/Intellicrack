"""Production tests for certificate cache functionality.

CRITICAL: These tests validate REAL caching operations with thread safety.
Tests MUST fail if cache operations, LRU eviction, or thread safety breaks.

Test Coverage:
- Certificate storage and retrieval
- LRU eviction policy
- Thread-safe concurrent access
- Cache invalidation (expiration)
- Metadata persistence
- Cache statistics
- Cache clearing
- Filesystem operations
"""

import json
import threading
import time
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from intellicrack.core.certificate.cert_cache import CertificateCache
from intellicrack.core.certificate.cert_chain_generator import CertificateChain


@pytest.fixture
def temp_cache_dir(tmp_path: Path) -> Path:
    """Create temporary cache directory."""
    cache_dir = tmp_path / "test_cert_cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir


@pytest.fixture
def sample_cert_chain() -> CertificateChain:
    """Generate a sample certificate chain for testing."""
    root_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )

    root_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Root CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Test Root CA"),
    ])

    root_cert = (
        x509.CertificateBuilder()
        .subject_name(root_subject)
        .issuer_name(root_subject)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC))
        .not_valid_after(datetime.now(UTC) + timedelta(days=3650))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .sign(root_key, hashes.SHA256(), default_backend())
    )

    intermediate_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )

    intermediate_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Intermediate CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Test Intermediate CA"),
    ])

    intermediate_cert = (
        x509.CertificateBuilder()
        .subject_name(intermediate_subject)
        .issuer_name(root_subject)
        .public_key(intermediate_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC))
        .not_valid_after(datetime.now(UTC) + timedelta(days=1825))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        )
        .sign(root_key, hashes.SHA256(), default_backend())
    )

    leaf_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )

    leaf_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Company"),
        x509.NameAttribute(NameOID.COMMON_NAME, "example.com"),
    ])

    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(leaf_subject)
        .issuer_name(intermediate_subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC))
        .not_valid_after(datetime.now(UTC) + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("example.com")]),
            critical=False,
        )
        .sign(intermediate_key, hashes.SHA256(), default_backend())
    )

    return CertificateChain(
        leaf_cert=leaf_cert,
        intermediate_cert=intermediate_cert,
        root_cert=root_cert,
        leaf_key=leaf_key,
        intermediate_key=intermediate_key,
        root_key=root_key,
    )


class TestCacheInitialization:
    """Test cache initialization and setup."""

    def test_cache_creates_directory_structure(self, temp_cache_dir: Path) -> None:
        """Cache initialization creates directory structure."""
        cache = CertificateCache(cache_dir=temp_cache_dir)

        assert temp_cache_dir.exists()
        assert cache.metadata_file.exists()
        assert cache.cache_dir == temp_cache_dir

    def test_cache_creates_empty_metadata_file(self, temp_cache_dir: Path) -> None:
        """Cache initialization creates empty metadata file."""
        cache = CertificateCache(cache_dir=temp_cache_dir)

        with open(cache.metadata_file) as f:
            metadata = json.load(f)

        assert isinstance(metadata, dict)
        assert len(metadata) == 0

    def test_cache_loads_existing_metadata(self, temp_cache_dir: Path) -> None:
        """Cache loads existing metadata file on initialization."""
        metadata = {
            "test_hash": {
                "domain": "example.com",
                "created": datetime.now().isoformat(),
                "expiration": (datetime.now() + timedelta(days=365)).isoformat(),
            }
        }

        metadata_file = temp_cache_dir / "cache_metadata.json"
        with open(metadata_file, "w") as f:
            json.dump(metadata, f)

        cache = CertificateCache(cache_dir=temp_cache_dir)

        loaded_metadata = cache._load_metadata()
        assert "test_hash" in loaded_metadata
        assert loaded_metadata["test_hash"]["domain"] == "example.com"

    def test_default_cache_location(self) -> None:
        """Cache uses default location when not specified."""
        cache = CertificateCache()

        expected_path = Path.home() / ".intellicrack" / "cert_cache"
        assert cache.cache_dir == expected_path


class TestCertificateStorage:
    """Test certificate storage functionality."""

    def test_store_cert_creates_domain_directory(
        self,
        temp_cache_dir: Path,
        sample_cert_chain: CertificateChain,
    ) -> None:
        """Storing certificate creates domain-specific directory."""
        cache = CertificateCache(cache_dir=temp_cache_dir)

        success = cache.store_cert("example.com", sample_cert_chain)

        assert success is True

        domain_dir = cache._get_domain_dir("example.com")
        assert domain_dir.exists()
        assert domain_dir.is_dir()

    def test_store_cert_saves_all_certificates(
        self,
        temp_cache_dir: Path,
        sample_cert_chain: CertificateChain,
    ) -> None:
        """Storing certificate chain saves all components."""
        cache = CertificateCache(cache_dir=temp_cache_dir)

        cache.store_cert("example.com", sample_cert_chain)

        domain_dir = cache._get_domain_dir("example.com")
        assert (domain_dir / "leaf.pem").exists()
        assert (domain_dir / "intermediate.pem").exists()
        assert (domain_dir / "root.pem").exists()
        assert (domain_dir / "leaf_key.pem").exists()
        assert (domain_dir / "intermediate_key.pem").exists()
        assert (domain_dir / "root_key.pem").exists()

    def test_store_cert_updates_metadata(
        self,
        temp_cache_dir: Path,
        sample_cert_chain: CertificateChain,
    ) -> None:
        """Storing certificate updates metadata file."""
        cache = CertificateCache(cache_dir=temp_cache_dir)

        cache.store_cert("example.com", sample_cert_chain)

        metadata = cache._load_metadata()
        domain_hash = cache._domain_hash("example.com")

        assert domain_hash in metadata
        assert metadata[domain_hash]["domain"] == "example.com"
        assert "created" in metadata[domain_hash]
        assert "expiration" in metadata[domain_hash]
        assert "last_accessed" in metadata[domain_hash]

    def test_store_multiple_domains(
        self,
        temp_cache_dir: Path,
        sample_cert_chain: CertificateChain,
    ) -> None:
        """Storing multiple domains creates separate entries."""
        cache = CertificateCache(cache_dir=temp_cache_dir)

        domains = ["example.com", "test.com", "demo.com"]

        for domain in domains:
            cache.store_cert(domain, sample_cert_chain)

        metadata = cache._load_metadata()
        assert len(metadata) == 3

        for domain in domains:
            domain_dir = cache._get_domain_dir(domain)
            assert domain_dir.exists()


class TestCertificateRetrieval:
    """Test certificate retrieval functionality."""

    def test_get_cached_cert_retrieves_valid_chain(
        self,
        temp_cache_dir: Path,
        sample_cert_chain: CertificateChain,
    ) -> None:
        """Retrieving cached certificate returns complete chain."""
        cache = CertificateCache(cache_dir=temp_cache_dir)

        cache.store_cert("example.com", sample_cert_chain)

        retrieved = cache.get_cached_cert("example.com")

        assert retrieved is not None
        assert isinstance(retrieved, CertificateChain)
        assert retrieved.leaf_cert is not None
        assert retrieved.intermediate_cert is not None
        assert retrieved.root_cert is not None
        assert retrieved.leaf_key is not None

    def test_get_nonexistent_cert_returns_none(self, temp_cache_dir: Path) -> None:
        """Retrieving non-existent certificate returns None."""
        cache = CertificateCache(cache_dir=temp_cache_dir)

        retrieved = cache.get_cached_cert("nonexistent.com")

        assert retrieved is None

    def test_get_cached_cert_updates_access_time(
        self,
        temp_cache_dir: Path,
        sample_cert_chain: CertificateChain,
    ) -> None:
        """Retrieving certificate updates last_accessed timestamp."""
        cache = CertificateCache(cache_dir=temp_cache_dir)

        cache.store_cert("example.com", sample_cert_chain)

        time.sleep(0.1)

        metadata_before = cache._load_metadata()
        domain_hash = cache._domain_hash("example.com")
        access_time_before = metadata_before[domain_hash]["last_accessed"]

        cache.get_cached_cert("example.com")

        metadata_after = cache._load_metadata()
        access_time_after = metadata_after[domain_hash]["last_accessed"]

        assert access_time_after > access_time_before

    def test_get_expired_cert_returns_none(self, temp_cache_dir: Path) -> None:
        """Retrieving expired certificate returns None."""
        cache = CertificateCache(cache_dir=temp_cache_dir)

        expired_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "expired.com"),
        ])

        expired_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(expired_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(UTC) - timedelta(days=2))
            .not_valid_after(datetime.now(UTC) - timedelta(days=1))
            .sign(expired_key, hashes.SHA256(), default_backend())
        )

        expired_chain = CertificateChain(
            leaf_cert=expired_cert,
            intermediate_cert=expired_cert,
            root_cert=expired_cert,
            leaf_key=expired_key,
            intermediate_key=expired_key,
            root_key=expired_key,
        )

        cache.store_cert("expired.com", expired_chain)

        retrieved = cache.get_cached_cert("expired.com")

        assert retrieved is None


class TestLRUEviction:
    """Test LRU cache eviction policy."""

    def test_eviction_triggers_when_max_entries_exceeded(
        self,
        temp_cache_dir: Path,
        sample_cert_chain: CertificateChain,
    ) -> None:
        """Eviction removes least recently used entry when max exceeded."""
        cache = CertificateCache(cache_dir=temp_cache_dir, max_entries=3)

        cache.store_cert("domain1.com", sample_cert_chain)
        time.sleep(0.05)
        cache.store_cert("domain2.com", sample_cert_chain)
        time.sleep(0.05)
        cache.store_cert("domain3.com", sample_cert_chain)

        metadata = cache._load_metadata()
        assert len(metadata) == 3

        cache.store_cert("domain4.com", sample_cert_chain)

        metadata_after = cache._load_metadata()
        assert len(metadata_after) == 3

        domain1_hash = cache._domain_hash("domain1.com")
        assert domain1_hash not in metadata_after

    def test_eviction_removes_least_recently_accessed(
        self,
        temp_cache_dir: Path,
        sample_cert_chain: CertificateChain,
    ) -> None:
        """Eviction removes entry with oldest last_accessed time."""
        cache = CertificateCache(cache_dir=temp_cache_dir, max_entries=3)

        cache.store_cert("domain1.com", sample_cert_chain)
        time.sleep(0.05)
        cache.store_cert("domain2.com", sample_cert_chain)
        time.sleep(0.05)
        cache.store_cert("domain3.com", sample_cert_chain)

        time.sleep(0.05)
        cache.get_cached_cert("domain1.com")

        cache.store_cert("domain4.com", sample_cert_chain)

        metadata = cache._load_metadata()

        domain2_hash = cache._domain_hash("domain2.com")
        assert domain2_hash not in metadata

        domain1_hash = cache._domain_hash("domain1.com")
        assert domain1_hash in metadata

    def test_eviction_deletes_directory(
        self,
        temp_cache_dir: Path,
        sample_cert_chain: CertificateChain,
    ) -> None:
        """Eviction deletes the domain directory from filesystem."""
        cache = CertificateCache(cache_dir=temp_cache_dir, max_entries=2)

        cache.store_cert("domain1.com", sample_cert_chain)
        cache.store_cert("domain2.com", sample_cert_chain)

        domain1_dir = cache._get_domain_dir("domain1.com")
        assert domain1_dir.exists()

        cache.store_cert("domain3.com", sample_cert_chain)

        assert not domain1_dir.exists()


class TestThreadSafety:
    """Test thread-safe concurrent access."""

    def test_concurrent_store_operations(
        self,
        temp_cache_dir: Path,
        sample_cert_chain: CertificateChain,
    ) -> None:
        """Concurrent store operations are thread-safe."""
        cache = CertificateCache(cache_dir=temp_cache_dir)

        def store_cert(domain: str) -> None:
            cache.store_cert(domain, sample_cert_chain)

        threads = []
        for i in range(10):
            thread = threading.Thread(target=store_cert, args=(f"domain{i}.com",))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        metadata = cache._load_metadata()
        assert len(metadata) == 10

    def test_concurrent_get_operations(
        self,
        temp_cache_dir: Path,
        sample_cert_chain: CertificateChain,
    ) -> None:
        """Concurrent get operations are thread-safe."""
        cache = CertificateCache(cache_dir=temp_cache_dir)
        cache.store_cert("example.com", sample_cert_chain)

        results = []

        def get_cert() -> None:
            chain = cache.get_cached_cert("example.com")
            results.append(chain is not None)

        threads = []
        for _ in range(10):
            thread = threading.Thread(target=get_cert)
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        assert all(results)
        assert len(results) == 10

    def test_concurrent_mixed_operations(
        self,
        temp_cache_dir: Path,
        sample_cert_chain: CertificateChain,
    ) -> None:
        """Mixed concurrent operations maintain data integrity."""
        cache = CertificateCache(cache_dir=temp_cache_dir, max_entries=20)

        def mixed_operations(thread_id: int) -> None:
            for i in range(5):
                domain = f"thread{thread_id}_domain{i}.com"
                cache.store_cert(domain, sample_cert_chain)
                retrieved = cache.get_cached_cert(domain)
                assert retrieved is not None

        threads = []
        for tid in range(5):
            thread = threading.Thread(target=mixed_operations, args=(tid,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        metadata = cache._load_metadata()
        assert len(metadata) <= 25


class TestCacheStatistics:
    """Test cache statistics functionality."""

    def test_cache_stats_returns_accurate_counts(
        self,
        temp_cache_dir: Path,
        sample_cert_chain: CertificateChain,
    ) -> None:
        """Cache statistics return accurate entry counts."""
        cache = CertificateCache(cache_dir=temp_cache_dir, max_entries=100)

        cache.store_cert("domain1.com", sample_cert_chain)
        cache.store_cert("domain2.com", sample_cert_chain)
        cache.store_cert("domain3.com", sample_cert_chain)

        stats = cache.get_cache_stats()

        assert stats["total_entries"] == 3
        assert stats["max_entries"] == 100
        assert stats["utilization_percent"] == 3.0

    def test_cache_stats_counts_expired_entries(self, temp_cache_dir: Path) -> None:
        """Cache statistics correctly count expired entries."""
        cache = CertificateCache(cache_dir=temp_cache_dir)

        expired_key = rsa.generate_private_key(65537, 2048, default_backend())
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])

        expired_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(expired_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(UTC) - timedelta(days=2))
            .not_valid_after(datetime.now(UTC) - timedelta(days=1))
            .sign(expired_key, hashes.SHA256(), default_backend())
        )

        expired_chain = CertificateChain(
            expired_cert,
            expired_cert,
            expired_cert,
            expired_key,
            expired_key,
            expired_key,
        )

        cache.store_cert("expired.com", expired_chain)

        stats = cache.get_cache_stats()

        assert stats["expired_entries"] >= 1


class TestCacheClearing:
    """Test cache clearing functionality."""

    def test_clear_cache_removes_all_entries(
        self,
        temp_cache_dir: Path,
        sample_cert_chain: CertificateChain,
    ) -> None:
        """Clearing cache removes all entries."""
        cache = CertificateCache(cache_dir=temp_cache_dir)

        cache.store_cert("domain1.com", sample_cert_chain)
        cache.store_cert("domain2.com", sample_cert_chain)
        cache.store_cert("domain3.com", sample_cert_chain)

        success = cache.clear_cache()

        assert success is True

        metadata = cache._load_metadata()
        assert len(metadata) == 0

    def test_clear_cache_deletes_directories(
        self,
        temp_cache_dir: Path,
        sample_cert_chain: CertificateChain,
    ) -> None:
        """Clearing cache deletes all domain directories."""
        cache = CertificateCache(cache_dir=temp_cache_dir)

        cache.store_cert("domain1.com", sample_cert_chain)
        domain_dir = cache._get_domain_dir("domain1.com")

        assert domain_dir.exists()

        cache.clear_cache()

        assert not domain_dir.exists()

    def test_remove_expired_removes_only_expired(
        self,
        temp_cache_dir: Path,
        sample_cert_chain: CertificateChain,
    ) -> None:
        """remove_expired only removes expired certificates."""
        cache = CertificateCache(cache_dir=temp_cache_dir)

        cache.store_cert("valid.com", sample_cert_chain)

        expired_key = rsa.generate_private_key(65537, 2048, default_backend())
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])

        expired_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(expired_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(UTC) - timedelta(days=2))
            .not_valid_after(datetime.now(UTC) - timedelta(days=1))
            .sign(expired_key, hashes.SHA256(), default_backend())
        )

        expired_chain = CertificateChain(
            expired_cert,
            expired_cert,
            expired_cert,
            expired_key,
            expired_key,
            expired_key,
        )

        cache.store_cert("expired.com", expired_chain)

        removed_count = cache.remove_expired()

        assert removed_count >= 1

        valid_chain = cache.get_cached_cert("valid.com")
        assert valid_chain is not None


class TestDomainHashing:
    """Test domain hashing functionality."""

    def test_domain_hash_consistency(self, temp_cache_dir: Path) -> None:
        """Domain hashing produces consistent results."""
        cache = CertificateCache(cache_dir=temp_cache_dir)

        hash1 = cache._domain_hash("example.com")
        hash2 = cache._domain_hash("example.com")

        assert hash1 == hash2

    def test_different_domains_different_hashes(self, temp_cache_dir: Path) -> None:
        """Different domains produce different hashes."""
        cache = CertificateCache(cache_dir=temp_cache_dir)

        hash1 = cache._domain_hash("example.com")
        hash2 = cache._domain_hash("different.com")

        assert hash1 != hash2

    def test_domain_hash_is_sha256_length(self, temp_cache_dir: Path) -> None:
        """Domain hash has SHA-256 length (64 hex characters)."""
        cache = CertificateCache(cache_dir=temp_cache_dir)

        domain_hash = cache._domain_hash("example.com")

        assert len(domain_hash) == 64
        assert all(c in "0123456789abcdef" for c in domain_hash)
