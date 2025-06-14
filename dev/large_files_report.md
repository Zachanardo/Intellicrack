# Large File Analysis Report

Found 18 files with more than 1000 lines.

**Total lines in large files:** 40,717
**Average lines per large file:** 2,262

## Critical Files (>2000 lines)

### intellicrack/ui/main_app.py (16,555 lines)
- **Classes:** 0
- **Functions:** 0
- **Action:** Manual review required

### intellicrack/utils/runner_functions.py (2,328 lines)
- **Classes:** 0
- **Functions:** 0
- **Action:** Manual review required

## High Priority Files (1500-2000 lines)

### scripts/cli/main.py (1,952 lines)
- **Recommendation:** Manual review required

### intellicrack/ui/dialogs/model_finetuning_dialog.py (1,891 lines)
- **Recommendation:** Manual review required

### intellicrack/hexview/hex_widget.py (1,875 lines)
- **Recommendation:** High priority: Consider splitting by functionality

### intellicrack/utils/exploitation.py (1,774 lines)
- **Recommendation:** Manual review required

### intellicrack/utils/additional_runners.py (1,653 lines)
- **Recommendation:** Manual review required

## Moderate Files (1000-1500 lines)

| File | Lines | Recommendation |
|------|-------|----------------|
| intellicrack/utils/tool_wrappers.py | 1,430 | Manual review required |
| intellicrack/hexview/ai_bridge.py | 1,429 | Manual review required |
| intellicrack/ai/model_manager_module.py | 1,233 | Manual review required |
| intellicrack/utils/binary_analysis.py | 1,131 | Manual review required |
| intellicrack/core/processing/distributed_manager.py | 1,128 | Manual review required |
| intellicrack/ai/enhanced_training_interface.py | 1,105 | Manual review required |
| intellicrack/utils/distributed_processing.py | 1,096 | Manual review required |
| models/create_ml_model.py | 1,053 | Manual review required |
| intellicrack/utils/internal_helpers.py | 1,043 | Manual review required |
| intellicrack/hexview/advanced_search.py | 1,025 | Split into 3 modules, grouping related classes |
| intellicrack/ui/dialogs/guided_workflow_wizard.py | 1,016 | Monitor size, split if continues growing |

## Refactoring Guidelines

1. **Single Responsibility:** Each module should have one clear purpose
2. **Cohesion:** Keep related functionality together
3. **Dependencies:** Minimize circular dependencies
4. **Testing:** Ensure tests cover functionality before splitting
5. **Documentation:** Update imports and documentation after splitting

## Next Steps

1. Address critical files first (>2000 lines)
2. Create new module structure before moving code
3. Update all imports after refactoring
4. Run tests to ensure functionality preserved
