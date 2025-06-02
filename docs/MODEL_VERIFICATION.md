# Intellicrack Model Verification System

The model verification system has been updated to be more flexible when downloading and verifying AI models, which allows it to handle model updates from providers without breaking functionality.

## Configuration Options

There are two ways to control model verification behavior:

### 1. In `models.json` (Permanent configuration)

The `models.json` file now supports a `verification_mode` field for each model:

```json
{
  "Q4_K_M": {
    "url": "https://huggingface.co/TheBloke/Mixtral-8x7B-v0.1-GGUF/resolve/main/mixtral-8x7b-v0.1.Q4_K_M.gguf",
    "sha256": "7a8053a361fac62d31c145e56f49e279fee1e8c7a39b547980198fc1bcf3b6c0",
    "description": "Mixtral 8x7B v0.1 - 4-bit Medium Quantization",
    "verification_mode": "optional"
  }
}
```

Supported `verification_mode` values:
- `required` (default): Strict verification, will fail if hash doesn't match
- `optional`: Will log a warning but continue with a hash mismatch
- `skip`: Same as optional, will proceed even with a hash mismatch

### 2. Bypass File (Manual override)

You can create a file named `bypass_verification` in the `models` directory to manually bypass verification for all models, regardless of their `verification_mode` settings.

To create this file automatically, run:
```
python bypass_model_verification.py
```

## How It Works

When downloading or checking an existing model:

1. The system first checks if a bypass file exists
2. Then it checks the `verification_mode` setting in models.json
3. If verification is required (and no bypass file exists), the hash must match
4. If verification is optional or a bypass file exists, a warning is shown but the model is used anyway
5. If no hash is provided in models.json, verification is skipped automatically

## Updating Models

When a model provider updates their model file:

1. If you're using `verification_mode: "optional"`, Intellicrack will automatically work with the new file
2. If you're using `verification_mode: "required"`, you'll need to update the hash in models.json
3. As a temporary solution, you can create the bypass file while waiting for an updated hash

## Troubleshooting

If you see a hash verification error, you have several options:

1. Update the hash in `models.json` to match the new file
2. Change `verification_mode` to `"optional"` in `models.json`
3. Run `python bypass_model_verification.py` to create a bypass file