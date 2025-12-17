"""Production tests for certificate cache validating real caching functionality.

Tests verify thread-safe LRU cache operations, persistent storage, expiration
handling, and concurrent access patterns using actual certificate chains.
"""

import pytest
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Generator

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtensionOID

from intellicrack.core.certificate.cert_cache import CertificateCache
from intellicrack.core.certificate.cert_chain_generator import CertificateChain


@pytest.fixture
def temp_cache_dir() -> Generator[Path, None, None]:
    """Create temporary cache directory for testing."""
    with TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_cert_chain() -> CertificateChain:
    """Generate a sample certificate chain for testing."""
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    intermediate_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    root_name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Intellicrack Test CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Intellicrack Root CA"),
    ])

    root_cert = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=2),
            critical=True,
        )
        .sign(root_key, hashes.SHA256())
    )

    intermediate_name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Intellicrack Test CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Intellicrack Intermediate CA"),
    ])

    intermediate_cert = (
        x509.CertificateBuilder()
        .subject_name(intermediate_name)
        .issuer_name(root_name)
        .public_key(intermediate_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=1),
            critical=True,
        )
        .sign(root_key, hashes.SHA256())
    )

    leaf_name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Domain"),
        x509.NameAttribute(NameOID.COMMON_NAME, "example.com"),
    ])

    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(intermediate_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("example.com")]),
            critical=False,
        )
        .sign(intermediate_key, hashes.SHA256())
    )

    return CertificateChain(
        leaf_cert=leaf_cert,
        intermediate_cert=intermediate_cert,
        root_cert=root_cert,
        leaf_key=leaf_key,
        intermediate_key=intermediate_key,
        root_key=root_key,
    )


class TestCertificateCacheInitialization:
    """Tests validating cache initialization and directory creation."""

    def test_cache_creates_directory_structure(self, temp_cache_dir: Path) -> None:
        """Cache creates directory structure on initialization."""
        cache = CertificateCache(cache_dir=temp_cache_dir, max_entries=100)

        assert temp_cache_dir.exists()
        assert cache.metadata_file.exists()
        assert cache.cache_dir == temp_cache_dir

    def test_cache_creates_metadata_file(self, temp_cache_dir: Path) -> None:
        """Cache creates metadata JSON file on initialization."""
        cache = CertificateCache(cache_dir=temp_cache_dir, max_entries=100)

        assert cache.metadata_file.exists()
        assert cache.metadata_file.name == "cache_metadata.json"

    def test_cache_uses_default_directory_when_none_provided(self) -> None:
        """Cache uses ~/.intellicrack/cert_cache/ when no directory provided."""
        cache = CertificateCache()

        expected_dir = Path.home() / ".intellicrack" / "cert_cache"
        assert cache.cache_dir == expected_dir


class TestCertificateStorageAndRetrieval:
    """Tests validating certificate storage and retrieval operations."""

    def test_store_and_retrieve_certificate_chain(
        self,
        temp_cache_dir: Path,
        sample_cert_chain: CertificateChain,
    ) -> None:
        """Store and retrieve complete certificate chain successfully."""
        cache = CertificateCache(cache_dir=temp_cache_dir, max_entries=100)

        domain = "example.com"
        stored = cache.store_cert(domain, sample_cert_chain)

        assert stored is True

        retrieved = cache.get_cached_cert(domain)

        assert retrieved is not None
        assert retrieved.leaf_cert.subject == sample_cert_chain.leaf_cert.subject
        assert retrieved.intermediate_cert.subject == sample_cert_chain.intermediate_cert.subject
        assert retrieved.root_cert.subject == sample_cert_chain.root_cert.subject

    def test_retrieve_nonexistent_domain_returns_none(
        self,
        temp_cache_dir: Path,
    ) -> None:
        """Retrieving non-existent domain returns None."""
        cache = CertificateCache(cache_dir=temp_cache_dir, max_entries=100)

        retrieved = cache.get_cached_cert("nonexistent.com")

        assert retrieved is None

    def test_stored_certificate_files_exist_on_disk(
        self,
        temp_cache_dir: Path,
        sample_cert_chain: CertificateChain,
    ) -> None:
        """Stored certificate creates all required files on disk."""
        cache = CertificateCache(cache_dir=temp_cache_dir, max_entries=100)

        domain = "example.com"
        cache.store_cert(domain, sample_cert_chain)

        domain_dir = cache._get_domain_dir(domain)

        assert (domain_dir / "leaf.pem").exists()
        assert (domain_dir / "intermediate.pem").exists()
        assert (domain_dir / "root.pem").exists()
        assert (domain_dir / "leaf_key.pem").exists()
        assert (domain_dir / "intermediate_key.pem").exists()
        assert (domain_dir / "root_key.pem").exists()

    def test_domain_hash_generates_consistent_hash(
        self,
        temp_cache_dir: Path,
    ) -> None:
        """Domain hash generates consistent SHA256 hash."""
        cache = CertificateCache(cache_dir=temp_cache_dir, max_entries=100)

        domain = "example.com"
        hash1 = cache._domain_hash(domain)
        hash2 = cache._domain_hash(domain)

        assert hash1 == hash2
        assert len(hash1) == 64


class TestCacheExpiration:
    """Tests validating certificate expiration handling."""

    def test_expired_certificate_returns_none(
        self,
        temp_cache_dir: Path,
    ) -> None:
        """Expired certificate is not returned from cache."""
        cache = CertificateCache(cache_dir=temp_cache_dir, max_entries=100)

        root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        intermediate_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        expired_leaf = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "expired.com")]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CA")]))
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow() - timedelta(days=365))
            .not_valid_after(datetime.utcnow() - timedelta(days=1))
            .sign(intermediate_key, hashes.SHA256())
        )

        intermediate_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CA")]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Root CA")]))
            .public_key(intermediate_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=365))
            .sign(root_key, hashes.SHA256())
        )

        root_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Root CA")]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Root CA")]))
            .public_key(root_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=365))
            .sign(root_key, hashes.SHA256())
        )

        expired_chain = CertificateChain(
            leaf_cert=expired_leaf,
            intermediate_cert=intermediate_cert,
            root_cert=root_cert,
            leaf_key=leaf_key,
            intermediate_key=intermediate_key,
            root_key=root_key,
        )

        cache.store_cert("expired.com", expired_chain)

        retrieved = cache.get_cached_cert("expired.com")

        assert retrieved is None

    def test_remove_expired_certificates(
        self,
        temp_cache_dir: Path,
    ) -> None:
        """Remove expired certificates from cache."""
        cache = CertificateCache(cache_dir=temp_cache_dir, max_entries=100)

        root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        intermediate_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        expired_leaf = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "expired.com")]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CA")]))
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow() - timedelta(days=365))
            .not_valid_after(datetime.utcnow() - timedelta(days=1))
            .sign(intermediate_key, hashes.SHA256())
        )

        intermediate_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CA")]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Root CA")]))
            .public_key(intermediate_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=365))
            .sign(root_key, hashes.SHA256())
        )

        root_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Root CA")]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Root CA")]))
            .public_key(root_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=365))
            .sign(root_key, hashes.SHA256())
        )

        expired_chain = CertificateChain(
            leaf_cert=expired_leaf,
            intermediate_cert=intermediate_cert,
            root_cert=root_cert,
            leaf_key=leaf_key,
            intermediate_key=intermediate_key,
            root_key=root_key,
        )

        cache.store_cert("expired.com", expired_chain)

        removed_count = cache.remove_expired()

        assert removed_count >= 1


class TestLRUEviction:
    """Tests validating LRU eviction policy."""

    def test_lru_eviction_when_exceeding_max_entries(
        self,
        temp_cache_dir: Path,
        sample_cert_chain: CertificateChain,
    ) -> None:
        """LRU eviction triggers when cache exceeds max entries."""
        cache = CertificateCache(cache_dir=temp_cache_dir, max_entries=3)

        for i in range(5):
            domain = f"example{i}.com"
            cache.store_cert(domain, sample_cert_chain)

        stats = cache.get_cache_stats()

        assert stats["total_entries"] <= 3

    def test_lru_evicts_least_recently_accessed(
        self,
        temp_cache_dir: Path,
        sample_cert_chain: CertificateChain,
    ) -> None:
        """LRU eviction removes least recently accessed entry."""
        cache = CertificateCache(cache_dir=temp_cache_dir, max_entries=2)

        cache.store_cert("example1.com", sample_cert_chain)
        cache.store_cert("example2.com", sample_cert_chain)

        cache.get_cached_cert("example1.com")

        time.sleep(0.01)

        cache.store_cert("example3.com", sample_cert_chain)

        retrieved1 = cache.get_cached_cert("example1.com")
        retrieved2 = cache.get_cached_cert("example2.com")

        assert retrieved1 is not None
        assert retrieved2 is None


class TestCacheStatistics:
    """Tests validating cache statistics calculation."""

    def test_cache_stats_total_entries(
        self,
        temp_cache_dir: Path,
        sample_cert_chain: CertificateChain,
    ) -> None:
        """Cache statistics correctly count total entries."""
        cache = CertificateCache(cache_dir=temp_cache_dir, max_entries=100)

        for i in range(5):
            cache.store_cert(f"example{i}.com", sample_cert_chain)

        stats = cache.get_cache_stats()

        assert stats["total_entries"] == 5

    def test_cache_stats_utilization_percentage(
        self,
        temp_cache_dir: Path,
        sample_cert_chain: CertificateChain,
    ) -> None:
        """Cache statistics calculate utilization percentage correctly."""
        cache = CertificateCache(cache_dir=temp_cache_dir, max_entries=10)

        for i in range(5):
            cache.store_cert(f"example{i}.com", sample_cert_chain)

        stats = cache.get_cache_stats()

        assert stats["utilization_percent"] == 50.0


class TestClearCache:
    """Tests validating cache clearing functionality."""

    def test_clear_cache_removes_all_entries(
        self,
        temp_cache_dir: Path,
        sample_cert_chain: CertificateChain,
    ) -> None:
        """Clear cache removes all stored certificates."""
        cache = CertificateCache(cache_dir=temp_cache_dir, max_entries=100)

        for i in range(5):
            cache.store_cert(f"example{i}.com", sample_cert_chain)

        cleared = cache.clear_cache()

        assert cleared is True

        stats = cache.get_cache_stats()
        assert stats["total_entries"] == 0

    def test_clear_cache_removes_filesystem_entries(
        self,
        temp_cache_dir: Path,
        sample_cert_chain: CertificateChain,
    ) -> None:
        """Clear cache removes certificate directories from filesystem."""
        cache = CertificateCache(cache_dir=temp_cache_dir, max_entries=100)

        cache.store_cert("example.com", sample_cert_chain)

        cache.clear_cache()

        cert_dirs = [d for d in temp_cache_dir.iterdir() if d.is_dir()]

        assert len(cert_dirs) == 0


class TestThreadSafety:
    """Tests validating thread-safe concurrent access."""

    def test_concurrent_certificate_storage(
        self,
        temp_cache_dir: Path,
        sample_cert_chain: CertificateChain,
    ) -> None:
        """Concurrent certificate storage is thread-safe."""
        cache = CertificateCache(cache_dir=temp_cache_dir, max_entries=1000)

        def store_cert(domain_index: int) -> None:
            domain = f"example{domain_index}.com"
            cache.store_cert(domain, sample_cert_chain)

        threads = [threading.Thread(target=store_cert, args=(i,)) for i in range(50)]

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()

        stats = cache.get_cache_stats()

        assert stats["total_entries"] == 50

    def test_concurrent_retrieval_and_storage(
        self,
        temp_cache_dir: Path,
        sample_cert_chain: CertificateChain,
    ) -> None:
        """Concurrent retrieval and storage operations are thread-safe."""
        cache = CertificateCache(cache_dir=temp_cache_dir, max_entries=1000)

        for i in range(10):
            cache.store_cert(f"initial{i}.com", sample_cert_chain)

        def read_certs() -> None:
            for i in range(10):
                cache.get_cached_cert(f"initial{i}.com")

        def write_certs(offset: int) -> None:
            for i in range(5):
                cache.store_cert(f"new{offset}_{i}.com", sample_cert_chain)

        read_threads = [threading.Thread(target=read_certs) for _ in range(5)]
        write_threads = [threading.Thread(target=write_certs, args=(i,)) for i in range(5)]

        all_threads = read_threads + write_threads

        for thread in all_threads:
            thread.start()

        for thread in all_threads:
            thread.join()

        stats = cache.get_cache_stats()

        assert stats["total_entries"] >= 10


class TestMetadataManagement:
    """Tests validating metadata file management."""

    def test_metadata_tracks_creation_time(
        self,
        temp_cache_dir: Path,
        sample_cert_chain: CertificateChain,
    ) -> None:
        """Metadata tracks certificate creation time."""
        cache = CertificateCache(cache_dir=temp_cache_dir, max_entries=100)

        before_store = datetime.now()
        cache.store_cert("example.com", sample_cert_chain)
        after_store = datetime.now()

        metadata = cache._load_metadata()
        domain_hash = cache._domain_hash("example.com")

        created_time = datetime.fromisoformat(metadata[domain_hash]["created"])

        assert before_store <= created_time <= after_store

    def test_metadata_updates_last_accessed_on_retrieval(
        self,
        temp_cache_dir: Path,
        sample_cert_chain: CertificateChain,
    ) -> None:
        """Metadata updates last accessed time on retrieval."""
        cache = CertificateCache(cache_dir=temp_cache_dir, max_entries=100)

        cache.store_cert("example.com", sample_cert_chain)

        time.sleep(0.01)

        before_access = datetime.now()
        cache.get_cached_cert("example.com")
        after_access = datetime.now()

        metadata = cache._load_metadata()
        domain_hash = cache._domain_hash("example.com")

        last_accessed = datetime.fromisoformat(metadata[domain_hash]["last_accessed"])

        assert before_access <= last_accessed <= after_access
