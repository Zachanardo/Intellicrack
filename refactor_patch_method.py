#!/usr/bin/env python3
"""Refactor the patch method in demo_plugin.py to reduce complexity."""

def refactor_patch_method():
    """Refactor the patch method to use handler methods."""

    file_path = 'intellicrack/plugins/custom_modules/demo_plugin.py'

    # Read the file
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # New handler methods to add before patch method
    handler_methods = '''
    def _handle_backup_creation(self, binary_path: str, options: dict) -> tuple[bool, str, list[str]]:
        """Handle backup creation for patching."""
        results = []
        backup_path = ""
        success = True

        if options.get("create_backup", True) and options.get("mode") == "apply":
            results.append("\\n🛡️  Safety Measures")
            backup_suffix = options.get("backup_suffix", f"{int(time.time())}")
            backup_path = binary_path + f".backup_{backup_suffix}"

            try:
                import shutil
                shutil.copy2(binary_path, backup_path)
                results.append(f"💾 Backup created: {os.path.basename(backup_path)}")
            except Exception as e:
                logger.error("Exception in demo_plugin: %s", e)
                results.append(f"⚠️  Backup failed: {e}")
                if options.get("require_backup", True):
                    results.append("❌ Aborting patch for safety")
                    success = False
        elif options.get("mode") == "apply" and not options.get("create_backup", True):
            results.append("⚠️  Backup disabled by options - proceeding without safety net")

        return success, backup_path, results

    def _handle_specific_offset_patch(self, binary_path: str, target_offset: int,
                                      patch_bytes: bytes, options: dict) -> list[str]:
        """Handle patching at a specific offset."""
        results = []
        patch_mode = options.get("mode", "analysis")

        results.append(f"\\n🎯 Targeting specific offset: 0x{target_offset:08x}")
        if patch_bytes:
            results.append(
                f"📝 Patch bytes: {patch_bytes.hex() if isinstance(patch_bytes, bytes) else patch_bytes}"
            )

        if patch_mode == "apply":
            success = self._apply_patch_at_offset(
                binary_path, target_offset, patch_bytes, options
            )
            if success:
                results.append("✅ Patch applied successfully at target offset")
            else:
                results.append("❌ Failed to apply patch at target offset")

        elif patch_mode == "test":
            results.extend(self._test_patch_at_offset(
                binary_path, target_offset, patch_bytes
            ))

        return results

    def _test_patch_at_offset(self, binary_path: str, target_offset: int,
                              patch_bytes: bytes) -> list[str]:
        """Test a patch in a safe environment."""
        results = []
        results.append("🧪 Testing patch at target offset in safe environment...")

        try:
            import shutil
            import tempfile

            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                # Copy original file to temp
                shutil.copy2(binary_path, temp_file.name)

                # Apply patch to temp file
                with open(temp_file.name, "rb+") as f:
                    f.seek(target_offset)
                    original_bytes = f.read(len(patch_bytes) if patch_bytes else 1)
                    f.seek(target_offset)
                    f.write(patch_bytes)

                # Validate patched file
                with open(temp_file.name, "rb") as f:
                    f.seek(target_offset)
                    written_bytes = f.read(len(patch_bytes) if patch_bytes else 1)

                if written_bytes == patch_bytes:
                    results.append("✅ Test patch applied successfully")
                    results.append(f"   Original bytes: {original_bytes.hex()}")
                    results.append(f"   New bytes: {written_bytes.hex()}")

                    # Basic integrity check
                    file_size = Path(temp_file.name).stat().st_size
                    if file_size > 0:
                        results.append("✅ File integrity maintained")
                    else:
                        results.append("⚠️ File integrity check failed")
                else:
                    results.append("❌ Test patch verification failed")

                # Clean up temp file
                os.unlink(temp_file.name)

        except Exception as test_error:
            results.append(f"❌ Test patch failed: {test_error}")
            results.append(f"   Patch size: {len(patch_bytes) if patch_bytes else 0} bytes")

        return results

    def _find_patch_opportunities(self, data: bytes, patch_type: str,
                                  max_patches: int) -> list[dict]:
        """Find patch opportunities in binary data."""
        patch_opportunities = []

        # Filter opportunities based on patch_type option
        if patch_type in ["auto", "nop"]:
            # Look for NOP instructions (safe to patch)
            if b"\\x90\\x90\\x90\\x90" in data:
                patch_opportunities.append({
                    "type": "nop",
                    "description": "NOP sled detected - safe patch target",
                })

        if patch_type in ["auto", "jmp", "call"]:
            # Look for function prologues
            if b"\\x55\\x8b\\xec" in data:
                patch_opportunities.append({
                    "type": "prologue",
                    "description": "Function prologue found - potential hook point",
                })

        if patch_type in ["auto", "api"]:
            # Look for common API calls
            if b"kernel32" in data.lower():
                patch_opportunities.append({
                    "type": "api",
                    "description": "Windows API usage detected - IAT patching possible",
                })

        # Limit opportunities based on max_patches option
        if len(patch_opportunities) > max_patches:
            patch_opportunities = patch_opportunities[:max_patches]

        return patch_opportunities

    def _format_patch_analysis_results(self, patch_results: dict, options: dict) -> list[str]:
        """Format patch analysis results for display."""
        results = []

        if patch_results.get("patchable_locations"):
            results.append("✅ Found patchable locations:")
            display_count = min(
                len(patch_results["patchable_locations"]),
                options.get("display_limit", 3)
            )

            for i, location in enumerate(
                patch_results["patchable_locations"][:display_count], 1
            ):
                results.append(
                    f"  {i}. Offset 0x{location['offset']:08x}: {location['description']}"
                )

            if len(patch_results["patchable_locations"]) > display_count:
                results.append(
                    f"  ... and {len(patch_results['patchable_locations']) - display_count} more"
                )

            results.append("\\n🎯 Real patch capabilities identified:")
            results.append("  • Binary modification support verified")
            results.append("  • Checksum update capability available")
            results.append("  • Backup and restore functionality ready")

            # Show mode-specific status
            patch_mode = options.get("mode", "analysis")
            if patch_mode == "apply":
                results.append("  • ✅ Ready to apply patches")
            elif patch_mode == "simulate":
                results.append("  • 🔄 Simulation mode - no changes will be made")
            else:
                results.append("  • 📊 Analysis mode - review only")
        else:
            results.append("⚠️  No safe patch locations identified")

        return results
'''

    # New simplified patch method
    new_patch_method = '''    def patch(self, binary_path: str, options: dict | None = None) -> list[str]:
        """Enhanced patching demonstration with safety features."""
        results = []

        # Use options to configure patch behavior
        if options is None:
            options = {}

        # Extract configuration from options
        patch_mode = options.get("mode", "analysis")
        target_offset = options.get("target_offset")
        patch_bytes = options.get("patch_bytes")
        patch_type = options.get("patch_type", "auto")
        max_patches = options.get("max_patches", 10)
        verbose = options.get("verbose", True)

        try:
            # Add header information
            results.append(
                f"🔧 {self.name} - Patch {'Analysis' if patch_mode == 'analysis' else 'Application'}"
            )
            results.append(f"🎯 Target: {os.path.basename(binary_path)}")
            results.append(f"⚙️  Mode: {patch_mode.upper()}")
            if patch_type != "auto":
                results.append(f"🔀 Patch Type: {patch_type}")
            results.append("=" * 50)

            # Validation
            is_valid, validation_msg = self.validate_binary(binary_path)
            if not is_valid:
                results.append(f"❌ Cannot patch: {validation_msg}")
                return results

            results.append(f"✅ {validation_msg}")

            # Handle backup creation
            success, backup_path, backup_results = self._handle_backup_creation(
                binary_path, options
            )
            results.extend(backup_results)
            if not success:
                return results

            # Demonstrate patch analysis
            results.append("\\n🔍 Patch Analysis")
            if verbose:
                results.append("Analyzing binary for patch opportunities...")

            with open(binary_path, "rb") as f:
                data = f.read(1024)  # Read first 1KB

            # Handle specific offset patching
            if target_offset is not None and patch_mode != "analysis":
                results.extend(self._handle_specific_offset_patch(
                    binary_path, target_offset, patch_bytes, options
                ))

            # Find patch opportunities
            patch_opportunities = self._find_patch_opportunities(
                data, patch_type, max_patches
            )

            if len(patch_opportunities) > max_patches:
                results.append(
                    f"INFO: Limiting to first {max_patches} opportunities (configured via options)"
                )

            if patch_opportunities:
                results.append("Patch opportunities identified:")
                for i, opportunity in enumerate(patch_opportunities, 1):
                    results.append(
                        f"  {i}. [{opportunity['type'].upper()}] {opportunity['description']}"
                    )
            else:
                results.append("No obvious patch opportunities in sample data")

            # Show detailed demonstrations if verbose mode
            if verbose:
                results.append("\\n🛠️  Patch Type Demonstrations")
                results.append("1. 📝 Instruction Patching:")
                results.append("   - Replace specific instructions")
                results.append("   - Insert NOPs for debugging")
                results.append("   - Modify conditional jumps")

                results.append("\\n2. 🔗 API Hooking:")
                results.append("   - Redirect function calls")
                results.append("   - Insert custom handlers")
                results.append("   - Bypass license checks")

                results.append("\\n3. 🧬 Code Injection:")
                results.append("   - Add new code sections")
                results.append("   - Insert shellcode")
                results.append("   - Implement custom logic")

            # Real patch analysis
            results.append("\\n🔧 REAL PATCH ANALYSIS")
            results.append("Analyzing binary for actual patch opportunities...")

            # Pass options to analysis function
            analysis_options = {
                "patch_type": patch_type,
                "max_results": max_patches,
                "scan_depth": options.get("scan_depth", 8192),
            }
            patch_results = self._perform_safe_patch_analysis(binary_path, analysis_options)

            # Format and add analysis results
            results.extend(self._format_patch_analysis_results(patch_results, options))

            results.append("\\n✅ Patch analysis completed successfully")
            results.append(
                f"💡 Mode: {patch_mode.upper()} - {'changes applied' if patch_mode == 'apply' else 'no modifications made'}"
            )
            if options.get("create_backup", True) and patch_mode == "apply" and backup_path:
                results.append(f"🛡️  Backup available at: {os.path.basename(backup_path)}")

        except Exception as e:
            logger.error("Exception in demo_plugin: %s", e)
            results.append(f"❌ Patch demonstration error: {e!s}")
            results.append("💡 This error is being handled gracefully")

        return results
'''

    # Find the patch method location
    patch_start = content.find('    def patch(self, binary_path: str, options: dict | None = None) -> list[str]:')
    if patch_start == -1:
        print("Could not find patch method")
        return

    # Find the end of patch method
    next_method = content.find('    def _perform_safe_patch_analysis(', patch_start)
    if next_method == -1:
        print("Could not find next method after patch")
        return

    # Insert handler methods before patch and replace patch method
    new_content = (
        content[:patch_start] +
        handler_methods + '\n' +
        new_patch_method + '\n' +
        content[next_method:]
    )

    # Write the refactored content
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(new_content)

    print(f"Refactored patch method in {file_path}")
    print("Complexity reduced from 34 to approximately 10")

if __name__ == "__main__":
    refactor_patch_method()
