import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

print("Testing Phase 5 imports...")

try:
    from intellicrack.core.exploitation.memory_framework import AdvancedMemoryOperations
    print("✓ Memory Framework")
except Exception as e:
    print("✗ Memory Framework:", str(e))

try:
    from intellicrack.core.unpacking.universal_unpacker import UniversalUnpacker
    print("✓ Universal Unpacker")
except Exception as e:
    print("✗ Universal Unpacker:", str(e))

try:
    from intellicrack.core.anti_analysis.titan_hide_engine import TitanHideEngine
    print("✓ TitanHide Engine")
except Exception as e:
    print("✗ TitanHide Engine:", str(e))

try:
    from intellicrack.core.reconstruction.import_rebuilder import ImportRebuilder
    print("✓ Import Rebuilder")
except Exception as e:
    print("✗ Import Rebuilder:", str(e))

try:
    from intellicrack.core.licensing.activation_bypass import ActivationBypass
    print("✓ Activation Bypass")
except Exception as e:
    print("✗ Activation Bypass:", str(e))

try:
    from intellicrack.core.devirtualization.vm_translator import VMTranslator
    print("✓ VM Translator")
except Exception as e:
    print("✗ VM Translator:", str(e))

try:
    from intellicrack.core.advanced_bypass.stealth_techniques import StealthTechniques
    print("✓ Stealth Techniques")
except Exception as e:
    print("✗ Stealth Techniques:", str(e))

try:
    from intellicrack.core.exploitation.exploitation_workflow import WorkflowOrchestrator
    print("✓ Workflow Orchestrator")
except Exception as e:
    print("✗ Workflow Orchestrator:", str(e))

print("Basic import test completed.")