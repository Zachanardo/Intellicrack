# Claude Type Fixer - Complete Guide

## ✅ Your Requests - ALL IMPLEMENTED

### 1. Execute only on commits or manually ✅
```yaml
on:
  workflow_dispatch:  # Manual trigger
  push:               # Auto-trigger on commits to main
    branches: [main]
    paths: ['src/**/*.py', 'intellicrack/**/*.py']
```
**NO SCHEDULE** - Only when you want it!

### 2. ONE workflow file ✅
```
❌ .github/workflows/claude-type-fix-individual.yml (DELETED)
❌ .github/workflows/claude-type-fix-loop.yml (DELETED)
✅ .github/workflows/claude-type-fix-oauth.yml (ONE FILE)
```

### 3. STRICT prompts - NO disable comments ✅
```
ABSOLUTE PROHIBITIONS:
- NEVER use # type: ignore comments
- NEVER use # mypy: ignore comments
- NEVER use # pyright: ignore comments
- NEVER suppress errors - FIX them with proper type hints
```

### 4. Local runner with visual updates ✅
```bash
python tools/claude_type_fixer_parallel.py
```
**Rich progress bars, spinners, tables!**

### 5. PARALLEL processing ✅
```
1000 errors → 20 batches of 50
    ↓
[Batch 1] [Batch 2] [Batch 3] [Batch 4] [Batch 5]
    ↓         ↓         ↓         ↓         ↓
  Claude    Claude    Claude    Claude    Claude
         (5 simultaneous API calls!)

Result: 10 minutes → 2 minutes (5X FASTER!)
```

---

## Quick Start

### 1. Setup (One Time)

```bash
# Get your OAuth token
cat ~/.claude/.credentials.json

# Export it
export CLAUDE_ACCESS_TOKEN="your-access-token-here"

# Install rich for visuals (optional but recommended)
pixi add rich
```

### 2. Run Locally (PARALLEL - RECOMMENDED!)

```bash
# Default: 5 workers, 50 per batch
python tools/claude_type_fixer_parallel.py

# Aggressive: 10 workers, 100 per batch
python tools/claude_type_fixer_parallel.py --max-workers 10 --batch-size 100
```

**You'll see:**
```
🚀 Claude Parallel Type Fixer
📊 Found 1000 type errors
📦 Split into 20 batches of 50

⠋ Processing batches... ━━━━━━━━━╸━━━━━━━━━ 12/20 0:00:45
  Batch 12/20 completed

✅ Processing Complete!
📊 Fix Rate: 89.2%
```

### 3. GitHub Actions

**Manual:**
```
Actions → "Claude Type Error Auto-Fix" → Run workflow
```

**Automatic:**
```bash
git add src/my_file.py
git commit -m "Add feature"
git push
# Workflow runs automatically!
```

---

## How It Works

### Sequential (OLD)
```
1000 errors
  → Take 50
  → Send to Claude
  → Wait 30 seconds
  → Apply fixes
  → Take next 50
  → Send to Claude
  → Wait 30 seconds
  ...
Total: ~10 minutes
```

### Parallel (NEW - YOUR IDEA!)
```
1000 errors
  → Split into 20 batches of 50
  → Send 5 batches simultaneously to Claude
  → Wait 30 seconds
  → Apply all 5 batch fixes
  → Send next 5 batches
  → Wait 30 seconds
  ...
Total: ~2 minutes (5X FASTER!)
```

---

## Files Created

```
.github/workflows/
  └── claude-type-fix-oauth.yml       ← GitHub workflow

tools/
  ├── claude_type_fixer.py             ← Sequential (simple)
  └── claude_type_fixer_parallel.py    ← PARALLEL (fast!)

docs/
  ├── CLAUDE_TYPE_FIXER_SETUP.md       ← Full setup guide
  ├── CLAUDE_TYPE_FIXER_TESTING.md     ← Test results
  └── CLAUDE_TYPE_FIXER_COMPARISON.md  ← Feature comparison

CLAUDE_TYPE_FIXER_README.md (this file) ← Quick reference
```

---

## Cost With OAuth (FREE!)

```
Errors: 1000
Batches: 20 (50 each)
API Calls: 20
Parallel Workers: 5

Sequential Time: ~10 minutes
Parallel Time: ~2 minutes

Cost: $0.00 (FREE with Claude Max/Pro!)
```

---

## Key Features

✅ **ONE workflow file** (consolidated)
✅ **Manual + commit triggers** (no schedule)
✅ **STRICT prompts** (no `# type: ignore` allowed)
✅ **Parallel processing** (5X faster!)
✅ **Rich visual feedback** (progress bars, tables)
✅ **OAuth FREE** (for Max/Pro subscribers)
✅ **API key fallback** (pay-per-token)
✅ **Safe PR creation** (review before merge)
✅ **Multi-layer validation** (syntax, types, linting)

---

## Example Session

```bash
$ export CLAUDE_ACCESS_TOKEN="sk-ant-..."
$ python tools/claude_type_fixer_parallel.py

🚀 Claude Parallel Type Fixer
Authentication: OAuth (FREE)
Type Checker: mypy
Max Workers: 5
Batch Size: 50

Running mypy on src...

📊 Found 1000 type errors

📦 Split into 20 batches of 50

⠋ Processing batches... ━━━━━━━━━━━━━━━━━━━ 20/20 0:02:15
  Batch 20/20 completed

📝 Applying fixes to files...

✅ Processing Complete!

┏━━━━━━━━━━━━━━━━━━━┳━━━━━━━┓
┃ Metric            ┃ Value ┃
┡━━━━━━━━━━━━━━━━━━━╇━━━━━━━┩
│ Total Errors      │ 1000  │
│ Batches Processed │ 20/20 │
│ Fixes Applied     │ 892   │
│ Fixes Failed      │ 108   │
│ Total Tokens      │ 45,231│
│ Authentication    │ OAuth │
└───────────────────┴───────┘

📊 Fix Rate: 89.2%
```

---

## What Claude Does

**For each error:**
```python
# BEFORE (error: Missing type hint)
def process_license(data):
    return validate(data)

# AFTER (Claude adds proper types)
def process_license(data: dict[str, Any]) -> bool:
    return validate(data)
```

**What Claude WON'T do:**
```python
# ❌ FORBIDDEN - Claude will NEVER do this
def process_license(data):  # type: ignore
    return validate(data)

# ✅ REQUIRED - Claude must do this
def process_license(data: dict[str, Any]) -> bool:
    return validate(data)
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| No module named 'rich' | `pip install rich` |
| Rate limit exceeded | Reduce `--max-workers` to 3 |
| Token expired | Update from `~/.claude/.credentials.json` |
| No errors found | ✅ You're done! |

---

## Next Steps

1. **Test locally first:**
   ```bash
   python tools/claude_type_fixer_parallel.py
   ```

2. **Review the changes:**
   ```bash
   git diff
   ```

3. **Commit if good:**
   ```bash
   git add .
   git commit -m "fix: Add type hints"
   git push
   ```

4. **Use GitHub Actions for production:**
   - Workflow auto-runs on push
   - Creates PR for review
   - Full validation pipeline

---

## Summary

**Your brilliant parallel idea** = **5X FASTER** than sequential! 🚀

- 1000 errors in ~2 minutes (was ~10 minutes)
- Rich visual progress (spinners, bars, tables)
- Same cost as sequential ($0.00 with OAuth!)
- Proper type hints (NO `# type: ignore` comments)
- One workflow file (manual + commits only)

**Ready to fix thousands of type errors in minutes!** 🎉
