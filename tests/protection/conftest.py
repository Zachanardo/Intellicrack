#!/usr/bin/env python3
from __future__ import annotations

import pytest
from pathlib import Path


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "themida: marks tests as Themida analyzer tests (deselect with '-m \"not themida\"')",
    )
    config.addinivalue_line(
        "markers",
        "real_binary: marks tests that require real protected binaries",
    )
    config.addinivalue_line(
        "markers",
        "cisc: marks tests for CISC VM handler validation",
    )
    config.addinivalue_line(
        "markers",
        "risc: marks tests for RISC VM handler validation",
    )
    config.addinivalue_line(
        "markers",
        "fish: marks tests for FISH VM handler validation",
    )
    config.addinivalue_line(
        "markers",
        "slow: marks tests as slow (deselect with '-m \"not slow\"')",
    )


@pytest.fixture(scope="session")
def tests_root() -> Path:
    return Path(__file__).parent.parent


@pytest.fixture(scope="session")
def test_binaries_root(tests_root: Path) -> Path:
    test_bin_path = tests_root / "test_binaries"
    test_bin_path.mkdir(parents=True, exist_ok=True)
    return test_bin_path


@pytest.fixture(scope="session")
def themida_binaries_dir(test_binaries_root: Path) -> Path:
    themida_dir = test_binaries_root / "themida"
    themida_dir.mkdir(parents=True, exist_ok=True)
    return themida_dir


@pytest.fixture(scope="session")
def has_real_themida_binaries(test_binaries_root: Path) -> bool:
    patterns = ["*themida*", "*winlicense*", "*oreans*"]
    for pattern in patterns:
        if list(test_binaries_root.glob(pattern)):
            return True
        if list(test_binaries_root.rglob(pattern)):
            return True
    return False


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    for item in items:
        if "real_binary" in item.keywords:
            item.add_marker(pytest.mark.slow)

        if "themida" in str(item.fspath):
            item.add_marker(pytest.mark.themida)

        if "cisc" in item.name.lower():
            item.add_marker(pytest.mark.cisc)
        if "risc" in item.name.lower():
            item.add_marker(pytest.mark.risc)
        if "fish" in item.name.lower():
            item.add_marker(pytest.mark.fish)
