# Environment Isolation Strategy

This document explains how Intellicrack ensures **strict isolation** from system-wide tools, always using tools from the pixi environment.

## Isolation Layers

### 1. Cargo Configuration (`.cargo/config.toml`)

Forces cargo to use pixi's Rust toolchain:

```toml
[env]
RUSTC = { value = "D:\\Intellicrack\\.pixi\\envs\\default\\Library\\bin\\rustc.exe", force = true }
CARGO = { value = "D:\\Intellicrack\\.pixi\\envs\\default\\Library\\bin\\cargo.exe", force = true }
RUSTUP_TOOLCHAIN = { value = "", force = true }

[build]
rustc = "D:\\Intellicrack\\.pixi\\envs\\default\\Library\\bin\\rustc.exe"
```

**Effect**: Any `cargo` command in the project will use pixi's Rust, even outside pixi shell.

### 2. VS Code Configuration (`.vscode/settings.json`)

Configures IDE to use pixi tools:

```json
{
  "python.defaultInterpreterPath": "${workspaceFolder}/.pixi/envs/default/python.exe",
  "rust-analyzer.server.path": "${workspaceFolder}/.pixi/envs/default/Library/bin/rust-analyzer.exe",
  "rust-analyzer.cargo.sysroot": "${workspaceFolder}/.pixi/envs/default/Library",
  "terminal.integrated.env.windows": {
    "RUSTC": "${workspaceFolder}/.pixi/envs/default/Library/bin/rustc.exe",
    "RUSTUP_TOOLCHAIN": ""
  }
}
```

**Effect**: IDE features (rust-analyzer, Python IntelliSense) use pixi environment exclusively.

### 3. Pixi Shell Hook

Pixi automatically prepends its paths when you run `pixi shell`:

```bash
PATH="/d/Intellicrack/.pixi/envs/default/Library/bin:$PATH"
```

**Effect**: All tools from pixi environment shadow system-wide installations.

### 4. Environment Variables

Set in `.cargo/config.toml` and `.vscode/settings.json`:

- `RUSTUP_TOOLCHAIN=""` - Disables rustup's automatic toolchain selection
- `RUSTC`, `CARGO` - Forces specific binaries
- `PYO3_PYTHON`, `PYTHONHOME` - Python integration uses pixi's Python

## How to Use

### Option 1: Always Use Pixi Shell (Recommended)

```bash
cd D:\Intellicrack
pixi shell

# Now all commands use pixi environment:
cargo build
python main.py
npm install
```

### Option 2: Use Pixi Run (For Single Commands)

```bash
pixi run cargo build
pixi run python main.py
```

### Option 3: Use Direnv (Automatic Activation)

1. Install direnv: `choco install direnv` or `scoop install direnv`
2. Add to shell config: `eval "$(direnv hook bash)"`
3. Allow the project: `cd D:\Intellicrack && direnv allow`
4. Environment auto-activates when you `cd` into the directory

## Verification

Run the verification task to ensure isolation:

```bash
pixi run verify-env
```

Expected output:
```
✓ Python: D:\Intellicrack\.pixi\envs\default\python.exe
✓ Rust: Using pixi environment
=== Environment Isolation Check ===
Python: /d/Intellicrack/.pixi/envs/default/python
Rustc: /d/Intellicrack/.pixi/envs/default/Library/bin/rustc
Cargo: /d/Intellicrack/.pixi/envs/default/Library/bin/cargo
Node: /d/Intellicrack/.pixi/envs/default/node
RUSTUP_TOOLCHAIN: <not set>
=================================
```

## Troubleshooting

### Problem: Cargo still uses system Rust

**Solution**: Delete `target/` directory and rebuild:
```bash
rm -rf target intellicrack-launcher/target
pixi run cargo build
```

### Problem: IDE (VS Code) not using pixi tools

**Solution**: Restart VS Code and reload window:
1. Press `Ctrl+Shift+P`
2. Run "Developer: Reload Window"

### Problem: Verification fails

**Solution**: Ensure you're in pixi shell:
```bash
pixi shell
pixi run verify-env
```

## Why This Matters

**Consistent builds**: Everyone on the team uses identical tool versions
**No "works on my machine"**: Pixi environment is reproducible
**Isolation from system**: System updates don't break the project
**Easy onboarding**: New developers just run `pixi install`
