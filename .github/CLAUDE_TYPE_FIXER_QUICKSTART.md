# Claude Type Fixer - Quick Start Guide

## ⚡ 5-Minute Setup

### Step 1: Get Your Claude OAuth Token (FREE for Max/Pro users)

**Linux/WSL:**

```bash
cat ~/.claude/.credentials.json | grep access_token
cat ~/.claude/.credentials.json | grep refresh_token
cat ~/.claude/.credentials.json | grep expires_at
```

**macOS:**

1. Open Keychain Access app
2. Search "claude"
3. Show password for all three values

**Windows:**

```powershell
type %USERPROFILE%\.claude\.credentials.json
```

### Step 2: Add to GitHub Secrets

Repository Settings → Secrets and variables → Actions → New secret

Add these 3 secrets:

- `CLAUDE_ACCESS_TOKEN` = your access_token value
- `CLAUDE_REFRESH_TOKEN` = your refresh_token value
- `CLAUDE_EXPIRES_AT` = your expires_at timestamp

### Step 3: Run the Workflow

Actions tab → "Claude Type Error Auto-Fix (OAuth + API Key)" → Run workflow

**Done!** The workflow will:

- Find type errors
- Fix them with Claude (using your FREE OAuth token)
- Create a PR for your review
- Show you detailed metrics

---

## 🎯 Common Commands

### Test Locally First

```bash
# Get your OAuth token
export CLAUDE_ACCESS_TOKEN=$(cat ~/.claude/.credentials.json | jq -r '.access_token')

# Run batch mode (recommended)
python tools/claude_type_fixer.py --mode batch --max-errors 10 --verbose

# Check the results
git diff
```

### GitHub Actions Runs

**Manual run with custom settings:**

- Go to Actions tab
- Select workflow
- Click "Run workflow"
- Set max errors (start with 10-20 for first run)
- Choose type checker (mypy recommended)
- Click "Run workflow"

**Check results:**

- View workflow summary for metrics
- Check PR for file changes
- Download artifacts for detailed logs

---

## 💰 Cost Comparison

| Method                     | Cost            | Best For                           |
| -------------------------- | --------------- | ---------------------------------- |
| **OAuth (Claude Max/Pro)** | $0.00           | Regular maintenance, ongoing fixes |
| **API Key**                | ~$0.01-0.10/run | One-time cleanup, enterprise       |

---

## 🔧 Configuration Cheat Sheet

### Change Schedule

Edit `.github/workflows/claude-type-fix-oauth.yml`:

```yaml
schedule:
    - cron: '0 2 * * 0' # Sunday 2am (default)
    - cron: '0 3 * * *' # Daily 3am
    - cron: '0 2 * * 1' # Monday 2am
```

### Process More Errors

Change default in workflow file:

```yaml
max_errors:
    default: '100' # Increase from 50
```

### Auto-Commit (No PR)

For trusted fixes only:

```yaml
create_pr:
    default: 'false' # Change from 'true'
```

---

## 🚨 Troubleshooting

| Issue                      | Fix                                        |
| -------------------------- | ------------------------------------------ |
| "No authentication method" | Add GitHub secrets (see Step 2)            |
| "Token refresh failed"     | Update secrets with fresh tokens           |
| "Syntax errors found"      | Workflow auto-rolls back - check artifacts |
| "More errors after fix"    | Reduce max_errors, try smaller batch       |

---

## ✅ Validation Checklist

Before merging the PR, verify:

- [ ] Type fixes are minimal and correct
- [ ] No logic changes introduced
- [ ] Imports properly organized (no circular imports)
- [ ] Tests still pass (check PR status)
- [ ] Code style consistent with project

---

## 📚 Full Documentation

See `docs/CLAUDE_TYPE_FIXER_SETUP.md` for:

- Detailed setup instructions
- Advanced configuration
- Security best practices
- FAQ and troubleshooting
- Integration examples

---

## 🎓 Tips for First Run

1. **Start small**: Run with `max_errors: 10` first
2. **Review carefully**: Check the PR thoroughly
3. **Test locally**: Pull the PR branch and run tests
4. **Merge when confident**: Don't rush the first merge
5. **Iterate**: Run again with higher max_errors after first success

---

## 📊 Success Metrics

A successful run shows:

- ✅ 80%+ errors fixed
- ✅ No new errors introduced
- ✅ All validation checks passed
- ✅ Tests still passing
- ✅ Minimal code changes per fix

If you don't see these, adjust `max_errors` down and try again.

---

**Need help?** Check the full documentation or open an issue!
