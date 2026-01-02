from __future__ import annotations

import json
import os
import tempfile
import time
from io import StringIO
from pathlib import Path
from typing import Any

import pytest

try:
    from intellicrack.cli.pipeline import (
        PipelineData,
        PipelineStage,
    )
    from intellicrack.cli.terminal_dashboard import (
        AnalysisStats,
        SessionInfo,
        SystemMetrics,
        TerminalDashboard,
    )
    from intellicrack.cli.progress_manager import ProgressManager

    MODULES_AVAILABLE = True
except ImportError as e:
    MODULES_AVAILABLE = False
    IMPORT_ERROR = str(e)


@pytest.fixture
def temp_dir(tmp_path: Path) -> Path:
    return tmp_path


@pytest.mark.skipif(not MODULES_AVAILABLE, reason=f"Modules not available: {'' if MODULES_AVAILABLE else IMPORT_ERROR}")
class TestPipelineDataFlowEffectiveness:

    def test_pipeline_data_serialization_integrity(self) -> None:
        KNOWN_CONTENT = {
            "binary": "protected.exe",
            "keys_extracted": ["RSA-2048-AAAA", "AES-256-BBBB"],
            "protection_level": "high"
        }
        KNOWN_METADATA = {
            "timestamp": 1234567890,
            "analyzer": "crypto_extractor",
            "confidence": 0.95
        }

        pipeline_data = PipelineData(
            content=KNOWN_CONTENT,
            metadata=KNOWN_METADATA,
            format="json"
        )

        json_str = pipeline_data.to_json()

        assert json_str is not None, "FAILED: Pipeline data serialization returned None"
        assert len(json_str) > 0, "FAILED: Pipeline data serialization returned empty string"

        try:
            parsed = json.loads(json_str)
        except json.JSONDecodeError as e:
            pytest.fail(f"FAILED: Pipeline data serialization produced invalid JSON: {e}")

        assert "content" in parsed, "FAILED: Serialized data missing 'content' field"
        assert "metadata" in parsed, "FAILED: Serialized data missing 'metadata' field"

        assert parsed["content"] == KNOWN_CONTENT, \
            f"FAILED: Content not preserved (got {parsed['content']}, expected {KNOWN_CONTENT})"
        assert parsed["metadata"] == KNOWN_METADATA, \
            f"FAILED: Metadata not preserved (got {parsed['metadata']}, expected {KNOWN_METADATA})"

    def test_pipeline_data_deserialization_accuracy(self) -> None:
        KNOWN_JSON = json.dumps({
            "content": {"license_check": "bypassed", "serial": "VALID-KEY-12345"},
            "metadata": {"tool": "keygen_generator", "success_rate": 0.92},
            "format": "json"
        })

        deserialized = PipelineData.from_json(KNOWN_JSON)

        assert deserialized is not None, "FAILED: Deserialization returned None"
        assert isinstance(deserialized, PipelineData), "FAILED: Deserialization didn't return PipelineData instance"

        assert deserialized.content.get("license_check") == "bypassed", \
            "FAILED: Deserialized content missing expected 'license_check' value"
        assert deserialized.content.get("serial") == "VALID-KEY-12345", \
            "FAILED: Deserialized content missing expected 'serial' value"
        assert deserialized.metadata.get("success_rate") == 0.92, \
            "FAILED: Deserialized metadata missing expected 'success_rate' value"

    def test_pipeline_data_round_trip_preservation(self) -> None:
        ORIGINAL_DATA = {
            "binary_path": "C:\\Windows\\System32\\notepad.exe",
            "protection_detected": ["ASLR", "DEP"],
            "bypass_techniques": ["ROP", "heap_spray"],
            "extracted_keys": [
                {"type": "RSA", "modulus": 12345678901234567890},
                {"type": "AES", "key_length": 256}
            ]
        }
        ORIGINAL_METADATA = {
            "analysis_duration": 45.67,
            "tools_used": ["frida", "ghidra", "radare2"],
            "confidence_score": 0.88
        }

        original = PipelineData(
            content=ORIGINAL_DATA,
            metadata=ORIGINAL_METADATA,
            format="json"
        )

        serialized = original.to_json()
        deserialized = PipelineData.from_json(serialized)

        assert deserialized.content == ORIGINAL_DATA, \
            "FAILED: Round-trip serialization lost content data"
        assert deserialized.metadata == ORIGINAL_METADATA, \
            "FAILED: Round-trip serialization lost metadata"
        assert deserialized.format == "json", \
            "FAILED: Round-trip serialization lost format"


@pytest.mark.skipif(not MODULES_AVAILABLE, reason=f"Modules not available: {'' if MODULES_AVAILABLE else IMPORT_ERROR}")
class TestPipelineStageProcessingEffectiveness:

    def test_custom_stage_processes_data_correctly(self) -> None:



        class LicenseKeyExtractorStage(PipelineStage):
            def process(self, input_data: PipelineData) -> PipelineData:
                binary_content = input_data.content.get("binary_data", b"")

                extracted_keys = []
                if b"LICENSE-KEY:" in binary_content:
                    start = binary_content.index(b"LICENSE-KEY:") + len(b"LICENSE-KEY:")
                    key = binary_content[start:start+16].decode('ascii', errors='ignore')
                    extracted_keys.append(key)

                return PipelineData(
                    content={"extracted_keys": extracted_keys},
                    metadata={
                        **input_data.metadata,
                        "stage": "license_key_extractor",
                    },
                    format="json",
                )


        KNOWN_BINARY = b"HEADER\x00\x00LICENSE-KEY:ABCD-1234-EFGH-56FOOTER"
        KNOWN_KEY = "ABCD-1234-EFGH-5"

        stage = LicenseKeyExtractorStage(name="test_extractor")

        input_data = PipelineData(
            content={"binary_data": KNOWN_BINARY},
            metadata={"source": "test"},
            format="json"
        )

        output_data = stage.process(input_data)

        assert output_data is not None, "FAILED: Stage processing returned None"
        assert "extracted_keys" in output_data.content, "FAILED: Stage didn't extract keys"
        assert len(output_data.content["extracted_keys"]) >= 1, \
                "FAILED: Stage didn't extract any keys from binary with known key"
        assert output_data.content["extracted_keys"][0] == KNOWN_KEY, \
                f"FAILED: Stage extracted wrong key (got {output_data.content['extracted_keys'][0]}, expected {KNOWN_KEY})"

    def test_pipeline_stage_chaining(self) -> None:
        class ProtectionDetectorStage(PipelineStage):
            def process(self, input_data: PipelineData) -> PipelineData:
                binary_path = input_data.content.get("binary_path", "")

                detected_protections = []
                if "vmprotect" in binary_path.lower():
                    detected_protections.append("VMProtect")
                if "themida" in binary_path.lower():
                    detected_protections.append("Themida")

                return PipelineData(
                    content={**input_data.content, "protections": detected_protections},
                    metadata={**input_data.metadata, "stage": "protection_detector"},
                    format="json"
                )

        class BypassGeneratorStage(PipelineStage):
            def process(self, input_data: PipelineData) -> PipelineData:
                protections = input_data.content.get("protections", [])

                bypass_strategies = []
                for prot in protections:
                    if prot == "VMProtect":
                        bypass_strategies.append("devirtualization")
                    elif prot == "Themida":
                        bypass_strategies.append("unpacking")

                return PipelineData(
                    content={**input_data.content, "bypass_strategies": bypass_strategies},
                    metadata={**input_data.metadata, "stage": "bypass_generator"},
                    format="json"
                )

        detector = ProtectionDetectorStage(name="detector")
        generator = BypassGeneratorStage(name="generator")

        KNOWN_BINARY_PATH = "C:\\samples\\vmprotect_protected.exe"

        initial_data = PipelineData(
            content={"binary_path": KNOWN_BINARY_PATH},
            metadata={"analysis_id": "test_001"},
            format="json"
        )

        stage1_output = detector.process(initial_data)

        assert "protections" in stage1_output.content, \
            "FAILED: Stage 1 didn't add protections to output"
        assert "VMProtect" in stage1_output.content["protections"], \
            "FAILED: Stage 1 didn't detect VMProtect from path"

        stage2_output = generator.process(stage1_output)

        assert "bypass_strategies" in stage2_output.content, \
            "FAILED: Stage 2 didn't add bypass strategies to output"
        assert "devirtualization" in stage2_output.content["bypass_strategies"], \
            "FAILED: Stage 2 didn't generate correct bypass strategy for VMProtect"


@pytest.mark.skipif(not MODULES_AVAILABLE, reason=f"Modules not available: {'' if MODULES_AVAILABLE else IMPORT_ERROR}")
class TestTerminalDashboardEffectiveness:

    def test_system_metrics_accuracy(self) -> None:
        metrics = SystemMetrics(
            cpu_percent=42.5,
            memory_percent=67.8,
            disk_usage=85.3,
            network_sent=1024000,
            network_recv=2048000,
            process_count=125,
            uptime=3600.0
        )

        assert metrics.cpu_percent == 42.5, \
            f"FAILED: CPU metric not stored correctly (got {metrics.cpu_percent}, expected 42.5)"
        assert metrics.memory_percent == 67.8, \
            f"FAILED: Memory metric not stored correctly (got {metrics.memory_percent}, expected 67.8)"
        assert metrics.network_sent == 1024000, \
            f"FAILED: Network sent metric not stored correctly (got {metrics.network_sent}, expected 1024000)"

    def test_analysis_stats_tracking(self) -> None:
        stats = AnalysisStats(
            total_binaries=100,
            analyses_completed=87,
            vulnerabilities_found=23,
            active_projects=5,
            cache_hits=450,
            cache_misses=50,
            analysis_time_avg=12.34
        )

        assert stats.total_binaries == 100, "FAILED: Total binaries not tracked correctly"
        assert stats.analyses_completed == 87, "FAILED: Completed analyses not tracked correctly"
        assert stats.vulnerabilities_found == 23, "FAILED: Vulnerabilities not tracked correctly"

        completion_rate = stats.analyses_completed / stats.total_binaries
        assert completion_rate == 0.87, \
            f"FAILED: Completion rate calculation incorrect (got {completion_rate}, expected 0.87)"

        cache_hit_rate = stats.cache_hits / (stats.cache_hits + stats.cache_misses)
        assert cache_hit_rate == 0.9, \
            f"FAILED: Cache hit rate calculation incorrect (got {cache_hit_rate}, expected 0.9)"

    def test_session_info_updates(self) -> None:
        session = SessionInfo()

        KNOWN_BINARY = "C:\\test\\protected.exe"
        KNOWN_PROJECT = "vmprotect_analysis"

        session.current_binary = KNOWN_BINARY
        session.current_project = KNOWN_PROJECT
        session.commands_executed = 15
        session.ai_queries = 7
        session.exports_created = 3

        assert session.current_binary == KNOWN_BINARY, \
            "FAILED: Current binary not tracked in session"
        assert session.current_project == KNOWN_PROJECT, \
            "FAILED: Current project not tracked in session"
        assert session.commands_executed == 15, \
            "FAILED: Commands executed not tracked correctly"
        assert session.ai_queries == 7, \
            "FAILED: AI queries not tracked correctly"

    def test_dashboard_metric_retrieval(self) -> None:
        dashboard = TerminalDashboard(update_interval=0.1)

        KNOWN_METRICS = SystemMetrics(
            cpu_percent=55.0,
            memory_percent=72.5,
            disk_usage=60.0
        )

        dashboard.system_metrics = KNOWN_METRICS

        retrieved_metrics = dashboard.get_system_metrics()

        assert retrieved_metrics is not None, "FAILED: Dashboard didn't return system metrics"
        assert retrieved_metrics.cpu_percent == 55.0, \
            "FAILED: Dashboard returned incorrect CPU metric"
        assert retrieved_metrics.memory_percent == 72.5, \
            "FAILED: Dashboard returned incorrect memory metric"

    def test_dashboard_analysis_stats_updates(self) -> None:
        dashboard = TerminalDashboard(update_interval=0.1)

        dashboard.update_analysis_stats(
            total_binaries=50,
            completed=45,
            vulnerabilities=12
        )

        stats = dashboard.get_analysis_stats()

        assert stats is not None, "FAILED: Dashboard didn't return analysis stats"
        assert stats.total_binaries == 50, "FAILED: Dashboard didn't update total binaries"
        assert stats.analyses_completed == 45, "FAILED: Dashboard didn't update completed analyses"
        assert stats.vulnerabilities_found == 12, "FAILED: Dashboard didn't update vulnerabilities found"


@pytest.mark.skipif(not MODULES_AVAILABLE, reason=f"Modules not available: {'' if MODULES_AVAILABLE else IMPORT_ERROR}")
class TestProgressManagerEffectiveness:

    def test_progress_tracking_accuracy(self) -> None:
        manager = ProgressManager()

        KNOWN_TOTAL = 100
        KNOWN_TASK_NAME = "Analyzing license keys"

        task_id = manager.add_task(
            name=KNOWN_TASK_NAME,
            total=KNOWN_TOTAL
        )

        assert task_id is not None, "FAILED: Progress manager didn't return task ID"

        for _ in range(50):
            manager.update_task(task_id, advance=1)

        progress = manager.get_task_progress(task_id)

        assert progress is not None, "FAILED: Progress manager didn't return task progress"
        assert progress.get("completed", 0) == 50, \
                f"FAILED: Progress tracking incorrect (got {progress.get('completed', 0)}, expected 50)"
        assert progress.get("total", 0) == KNOWN_TOTAL, \
                f"FAILED: Total not tracked correctly (got {progress.get('total', 0)}, expected {KNOWN_TOTAL})"

        percentage = (progress.get("completed", 0) / progress.get("total", 1)) * 100
        assert abs(percentage - 50.0) < 0.1, \
                f"FAILED: Progress percentage incorrect (got {percentage}%, expected 50%)"

    def test_multiple_task_tracking(self) -> None:
        manager = ProgressManager()

        TASKS = [
            {"name": "Extracting keys", "total": 10},
            {"name": "Generating keygens", "total": 20},
            {"name": "Bypassing protections", "total": 15}
        ]

        task_ids = []
        for task_config in TASKS:
            task_id = manager.add_task(
                name=task_config["name"],
                total=task_config["total"]
            )
            task_ids.append(task_id)

        manager.update_task(task_ids[0], completed=10)
        manager.update_task(task_ids[1], completed=15)
        manager.update_task(task_ids[2], completed=5)

        task0_progress = manager.get_task_progress(task_ids[0])
        task1_progress = manager.get_task_progress(task_ids[1])
        task2_progress = manager.get_task_progress(task_ids[2])

        assert task0_progress.get("completed") == 10, \
            "FAILED: Task 0 progress not tracked correctly"
        assert task1_progress.get("completed") == 15, \
            "FAILED: Task 1 progress not tracked correctly"
        assert task2_progress.get("completed") == 5, \
            "FAILED: Task 2 progress not tracked correctly"

        task0_percentage = (task0_progress.get("completed") / task0_progress.get("total")) * 100
        task1_percentage = (task1_progress.get("completed") / task1_progress.get("total")) * 100

        assert task0_percentage == 100.0, \
            f"FAILED: Task 0 completion percentage incorrect (got {task0_percentage}%, expected 100%)"
        assert task1_percentage == 75.0, \
            f"FAILED: Task 1 completion percentage incorrect (got {task1_percentage}%, expected 75%)"


@pytest.mark.skipif(not MODULES_AVAILABLE, reason=f"Modules not available: {'' if MODULES_AVAILABLE else IMPORT_ERROR}")
class TestOutputFormattingEffectiveness:

    def test_json_output_validity(self) -> None:
        analysis_results = {
            "binary": "protected.exe",
            "protections": ["VMProtect", "Themida"],
            "keys_extracted": [
                {"type": "RSA", "size": 2048},
                {"type": "AES", "size": 256}
            ],
            "bypass_success": True,
            "confidence": 0.93
        }

        json_output = json.dumps(analysis_results, indent=2)

        assert json_output is not None, "FAILED: JSON output generation returned None"
        assert json_output != "", "FAILED: JSON output is empty"

        try:
            parsed = json.loads(json_output)
        except json.JSONDecodeError as e:
            pytest.fail(f"FAILED: JSON output is not valid JSON: {e}")

        assert parsed["binary"] == "protected.exe", \
                "FAILED: JSON output missing binary name"
        assert len(parsed["protections"]) == 2, \
                "FAILED: JSON output missing protections"
        assert parsed["bypass_success"] is True, \
                "FAILED: JSON output missing bypass success flag"

    def test_csv_output_structure(self) -> None:
        csv_data = (
            "binary,protection,bypass_status,confidence\n"
            + "app1.exe,VMProtect,success,0.95\n"
        )
        csv_data += "app2.exe,Themida,success,0.88\n"
        csv_data += "app3.exe,None,N/A,1.00\n"

        lines = csv_data.strip().split('\n')

        assert len(lines) == 4, \
                f"FAILED: CSV output has wrong number of lines (got {len(lines)}, expected 4)"

        header = lines[0].split(',')
        assert header == ["binary", "protection", "bypass_status", "confidence"], \
                "FAILED: CSV header structure incorrect"

        row1 = lines[1].split(',')
        assert row1[0] == "app1.exe", "FAILED: CSV row 1 binary name incorrect"
        assert row1[1] == "VMProtect", "FAILED: CSV row 1 protection incorrect"
        assert row1[2] == "success", "FAILED: CSV row 1 bypass status incorrect"
        assert float(row1[3]) == 0.95, "FAILED: CSV row 1 confidence incorrect"

    def test_text_report_formatting(self) -> None:
        report = "" + "=== Intellicrack Analysis Report ===\n"
        report += "Binary: protected.exe\n"
        report += "Protections Detected: VMProtect, Themida\n"
        report += "Keys Extracted: 3\n"
        report += "Bypass Status: SUCCESS\n"
        report += "Confidence: 92%\n"

        assert "Intellicrack Analysis Report" in report, \
                "FAILED: Text report missing title"
        assert "protected.exe" in report, \
                "FAILED: Text report missing binary name"
        assert "VMProtect" in report and "Themida" in report, \
                "FAILED: Text report missing protection names"
        assert "SUCCESS" in report, \
                "FAILED: Text report missing bypass status"


@pytest.mark.skipif(not MODULES_AVAILABLE, reason=f"Modules not available: {'' if MODULES_AVAILABLE else IMPORT_ERROR}")
class TestBatchProcessingEffectiveness:

    def test_batch_analysis_completion(self, temp_dir: Path) -> None:
        KNOWN_BINARIES = [
            "sample1.exe",
            "sample2.exe",
            "sample3.exe",
            "sample4.exe",
            "sample5.exe"
        ]

        for binary_name in KNOWN_BINARIES:
            binary_path = temp_dir / binary_name
            binary_path.write_bytes(b"PE\x00\x00TEST_BINARY_DATA")

        batch_results = {}

        for binary_name in KNOWN_BINARIES:
            binary_path = temp_dir / binary_name

            result = {
                "binary": binary_name,
                "analyzed": True,
                "protections": ["test_protection"],
                "status": "complete"
            }
            batch_results[binary_name] = result

        assert len(batch_results) == len(KNOWN_BINARIES), \
            f"FAILED: Batch processing incomplete (processed {len(batch_results)}, expected {len(KNOWN_BINARIES)})"

        for binary_name in KNOWN_BINARIES:
            assert binary_name in batch_results, \
                f"FAILED: Batch processing missing result for {binary_name}"
            assert batch_results[binary_name]["status"] == "complete", \
                f"FAILED: Batch processing didn't complete for {binary_name}"

    def test_concurrent_processing_results(self, temp_dir: Path) -> None:
        KNOWN_TASK_COUNT = 10

        results = []
        for i in range(KNOWN_TASK_COUNT):
            result = {
                "task_id": i,
                "binary": f"test{i}.exe",
                "keys_extracted": i % 3,
                "success": True
            }
            results.append(result)

        assert len(results) == KNOWN_TASK_COUNT, \
            f"FAILED: Concurrent processing incomplete (got {len(results)}, expected {KNOWN_TASK_COUNT})"

        success_count = sum(bool(r["success"])
                        for r in results)
        assert success_count == KNOWN_TASK_COUNT, \
            f"FAILED: Not all concurrent tasks succeeded (got {success_count}/{KNOWN_TASK_COUNT})"

        total_keys = sum(r["keys_extracted"] for r in results)
        assert total_keys > 0, \
            "FAILED: Concurrent processing didn't extract any keys"

    def test_batch_result_aggregation(self) -> None:
        INDIVIDUAL_RESULTS = [
            {"binary": "app1.exe", "keys": 2, "protections": 1, "success": True},
            {"binary": "app2.exe", "keys": 3, "protections": 2, "success": True},
            {"binary": "app3.exe", "keys": 1, "protections": 1, "success": False},
            {"binary": "app4.exe", "keys": 4, "protections": 3, "success": True},
        ]

        aggregated = {
            "total_binaries": len(INDIVIDUAL_RESULTS),
            "total_keys_extracted": sum(r["keys"] for r in INDIVIDUAL_RESULTS),
            "total_protections_detected": sum(r["protections"] for r in INDIVIDUAL_RESULTS),
            "success_count": sum(bool(r["success"])
                             for r in INDIVIDUAL_RESULTS),
        }

        assert aggregated["total_binaries"] == 4, \
            "FAILED: Aggregation didn't count all binaries"
        assert aggregated["total_keys_extracted"] == 10, \
            f"FAILED: Aggregation calculated wrong key count (got {aggregated['total_keys_extracted']}, expected 10)"
        assert aggregated["total_protections_detected"] == 7, \
            f"FAILED: Aggregation calculated wrong protection count (got {aggregated['total_protections_detected']}, expected 7)"
        assert aggregated["success_count"] == 3, \
            f"FAILED: Aggregation calculated wrong success count (got {aggregated['success_count']}, expected 3)"

        success_rate = aggregated["success_count"] / aggregated["total_binaries"]
        assert success_rate == 0.75, \
            f"FAILED: Success rate calculation incorrect (got {success_rate}, expected 0.75)"
