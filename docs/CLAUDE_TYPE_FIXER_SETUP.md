# Claude Type Error Auto-Fixer Setup Guide

## Overview

Automated Python type error fixing using Claude AI via GitHub Actions. Supports both **Claude OAuth** (FREE for Max/Pro subscribers) and **Anthropic API Key** (pay-per-token) authentication.

## 🎯 Benefits

- ✅ **Automated** - Fixes hundreds of type errors automatically
- 💰 **FREE** - Uses your Claude Max/Pro subscription (OAuth)
- 🔒 **Safe** - Creates pull requests for review before merging
- ✨ **Smart** - Claude understands context and applies minimal fixes
- 📊 **Tracked** - Full metrics and reporting

## 🔧 Setup Instructions

### Option 1: OAuth Authentication (RECOMMENDED - FREE for Max/Pro users)

#### Step 1: Get Your Claude OAuth Tokens

**On Linux/WSL:**
```bash
cat ~/.claude/.credentials.json
```

**On macOS:**
1. Open Keychain Access
2. Search for "claude"
3. Double-click the entry
4. Click "Show password"

**On Windows:**
```powershell
# If you have Claude Code CLI installed
type %USERPROFILE%\.claude\.credentials.json
```

You'll find three values:
- `access_token`
- `refresh_token`
- `expires_at`

#### Step 2: Add GitHub Secrets

Go to your repository settings → Secrets and variables → Actions → New repository secret

Add these three secrets:

1. **CLAUDE_ACCESS_TOKEN**
   - Value: Your `access_token` from credentials.json

2. **CLAUDE_REFRESH_TOKEN**
   - Value: Your `refresh_token` from credentials.json

3. **CLAUDE_EXPIRES_AT**
   - Value: Your `expires_at` timestamp from credentials.json

**Important**: The workflow automatically refreshes tokens when they expire!

### Option 2: API Key Authentication (Fallback)

If you don't have Claude Max/Pro, or prefer API key authentication:

#### Step 1: Get Anthropic API Key

1. Go to https://console.anthropic.com/
2. Navigate to API Keys section
3. Create a new API key

#### Step 2: Add GitHub Secret

Go to your repository settings → Secrets and variables → Actions → New repository secret

Add:
- **Name**: `ANTHROPIC_API_KEY`
- **Value**: Your Anthropic API key

**Cost**: ~$3 per million tokens (~$0.01-0.10 per run depending on error count)

## 📋 Usage

### Manual Trigger

1. Go to Actions tab in GitHub
2. Select "Claude Type Error Auto-Fix (OAuth + API Key)"
3. Click "Run workflow"
4. Configure options:
   - **Max errors**: How many errors to process (default: 50)
   - **Checker**: `mypy` or `pyright`
   - **Create PR**: true for safety, false for direct commit

### Scheduled Runs

The workflow runs automatically every Sunday at 2 AM UTC. Edit `.github/workflows/claude-type-fix-oauth.yml` to change the schedule:

```yaml
schedule:
  - cron: '0 2 * * 0'  # Change this line
```

Cron syntax: `minute hour day month weekday`

## 🔍 How It Works

1. **Detect** - Runs type checker (mypy/pyright) on codebase
2. **Authenticate** - Uses OAuth tokens (primary) or API key (fallback)
3. **Fix** - Sends errors to Claude for intelligent fixing
4. **Validate** - Multi-layer validation:
   - Python syntax check
   - Type checker re-run
   - Linting validation
   - Test suite execution
5. **Review** - Creates pull request with detailed summary
6. **Merge** - You review and merge when satisfied

## 📊 Understanding the Results

After each run, check:

### GitHub Actions Summary

Shows:
- Original error count
- Errors fixed
- Errors remaining
- Authentication method used
- Token usage (if API key)

### Pull Request

Contains:
- List of files modified
- Before/after error counts
- Validation results
- Review checklist

### Artifacts

Download `type-fix-results-*` for:
- `type_errors.txt` - Original errors detected
- `claude_response.txt` - Claude's response with fixes
- `verification_results.txt` - Post-fix validation results

## 🎛️ Configuration

### Adjust Error Batch Size

For large codebases with many errors, process in smaller chunks:

```yaml
inputs:
  max_errors:
    default: '25'  # Process 25 at a time
```

### Change Type Checker

Switch between mypy and pyright:

```yaml
inputs:
  checker:
    default: 'pyright'  # or 'mypy'
```

### Disable Auto-PR Creation

For trusted automated fixes:

```yaml
inputs:
  create_pr:
    default: 'false'  # Commits directly to main
```

## 🚨 Troubleshooting

### "No authentication method available"

**Problem**: Neither OAuth tokens nor API key are set.

**Solution**: Follow setup instructions above to add secrets.

### "OAuth token refresh failed"

**Problem**: Refresh token is invalid or expired.

**Solution**:
1. Get new tokens from `~/.claude/.credentials.json`
2. Update GitHub secrets with new values

### "Fixes introduced MORE errors"

**Problem**: Claude's fixes created additional type errors.

**Solution**:
- Workflow automatically rolls back changes
- Try processing fewer errors at once (reduce `max_errors`)
- Check `claude_response.txt` artifact to see what Claude attempted

### "Syntax errors found"

**Problem**: Claude generated invalid Python code.

**Solution**:
- Workflow automatically rolls back
- Report issue with the specific error in artifacts
- This is rare but can happen with complex fixes

## 💡 Best Practices

### Start Small
- First run: Set `max_errors: 10` to test
- Verify PR looks good
- Gradually increase to 50-100

### Review PRs Thoroughly
- Check that fixes don't change logic
- Verify type hints are correct
- Ensure imports are properly organized

### Prioritize Critical Errors
- Fix actual type mismatches first (e.g., `Argument 1 has incompatible type`)
- Add missing type hints second
- Style improvements last

### Use OAuth for Regular Maintenance
- FREE with Max/Pro subscription
- Automatic token refresh
- Ideal for scheduled weekly runs

### Use API Key for Large Cleanup
- Pay-per-token model
- Better for one-time bulk fixes
- Faster (no OAuth token refresh needed)

## 📈 Cost Analysis

### OAuth (Claude Max/Pro)
- **Cost**: $0.00 (included in subscription)
- **Limit**: Subject to Claude Max usage limits
- **Best for**: Regular maintenance, ongoing cleanup

### API Key
- **Cost**: ~$3 per million tokens
- **Typical run**: 10,000-50,000 tokens = $0.03-0.15
- **Large cleanup**: 100,000+ tokens = $0.30+
- **Best for**: One-time bulk fixes, enterprise users

## 🔐 Security Considerations

### Token Security
- Never commit tokens to git
- Use GitHub secrets exclusively
- Rotate tokens periodically

### Code Review
- Always review PRs before merging
- Test locally if unsure about fixes
- Check that tests pass

### Workflow Permissions
- Minimal permissions granted
- Read codebase + write PRs only
- No access to other secrets

## 🎓 Advanced Usage

### Local Testing

Use the local CLI tool:

```bash
# With OAuth
export ANTHROPIC_API_KEY="your-claude-oauth-access-token"
python tools/claude_type_fixer.py --mode batch --max-errors 50

# With API key
export ANTHROPIC_API_KEY="your-anthropic-api-key"
python tools/claude_type_fixer.py --mode batch --max-errors 50

# Individual mode (one error at a time)
python tools/claude_type_fixer.py --mode individual --max-iterations 10

# Different type checker
python tools/claude_type_fixer.py --checker pyright --mode batch
```

### Custom Scheduling

Edit the cron schedule for different frequencies:

```yaml
# Daily at 3 AM
- cron: '0 3 * * *'

# Twice a week (Monday & Thursday at 2 AM)
- cron: '0 2 * * 1,4'

# First day of every month
- cron: '0 0 1 * *'
```

### Integration with CI/CD

Add type fix validation to PR checks:

```yaml
name: Validate Type Fixes

on:
  pull_request:
    paths:
      - 'src/**/*.py'

jobs:
  check-types:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: prefix-dev/setup-pixi@v0.8.1
      - name: Check for new type errors
        run: |
          pixi run mypy src/ --no-error-summary | tee current_errors.txt
          ERROR_COUNT=$(grep -c "error:" current_errors.txt || echo "0")
          if [ "$ERROR_COUNT" -gt "0" ]; then
            echo "::error::PR introduces $ERROR_COUNT new type errors"
            exit 1
          fi
```

## 📚 Resources

- [Claude Code Documentation](https://docs.claude.com/en/docs/claude-code)
- [Anthropic API Reference](https://docs.anthropic.com/en/api/getting-started)
- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [MyPy Documentation](https://mypy.readthedocs.io/)
- [Pyright Documentation](https://microsoft.github.io/pyright/)

## ❓ FAQ

**Q: Can I use both OAuth and API key?**
A: Yes! The workflow tries OAuth first (free), then falls back to API key automatically.

**Q: How often should I run this?**
A: Weekly scheduled runs work well for most projects. Adjust based on your development velocity.

**Q: Will this fix all my type errors?**
A: It handles most common cases (missing hints, simple type mismatches). Complex generic types or circular imports may need manual fixing.

**Q: Is my code sent to Anthropic's servers?**
A: Yes, code context is sent to Claude API for analysis. Don't use for proprietary/sensitive code without proper authorization.

**Q: Can I customize what Claude fixes?**
A: Yes, edit the system prompt and instructions in the workflow file to adjust Claude's behavior.

## 🤝 Contributing

Found a bug or want to improve the workflow? Submit issues or PRs to the repository!

## 📄 License

Part of the Intellicrack project - see main repository LICENSE.
