"""Adobe License Bypass Compiler - Creates standalone EXE from Frida script."""

import json
import os
import platform
import shutil
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path

from intellicrack.core.config_manager import get_config
from intellicrack.logger import logger
from intellicrack.utils.binary.binary_utils import compute_file_hash


class AdobeLicenseCompiler:
    """Compiles adobe_bypass.js into standalone AdobeLicenseX.exe."""

    def __init__(self):
        self.config = get_config()
        self.adobe_config = self.config.get("adobe_license_compiler", {})

        self.script_dir = Path(__file__).parent.parent.parent / "scripts" / "frida"
        self.bypass_script = self.script_dir / "adobe_bypass.js"
        self.temp_dir = None

        # Get deployment configuration
        deployment_config = self.adobe_config.get("deployment", {})
        service_name = deployment_config.get("service_name", "AdobeLicenseX")
        self.exe_name = f"{service_name}.exe"

        # Configure startup folder based on settings
        if deployment_config.get("startup_folder", True):
            self.startup_folder = (
                Path(os.environ.get("APPDATA", ""))
                / "Microsoft"
                / "Windows"
                / "Start Menu"
                / "Programs"
                / "Startup"
            )
        else:
            self.startup_folder = Path(os.environ.get("PROGRAMDATA", "")) / service_name

        # Validate platform compatibility
        if not self._is_windows():
            raise RuntimeError("Adobe License Compiler is only supported on Windows platforms")

    def _is_windows(self):
        """Check if running on Windows platform."""
        return platform.system().lower() == "windows"

    def _get_architecture(self):
        """Get system architecture for Node.js downloads."""
        machine = platform.machine().lower()
        if machine in ("amd64", "x86_64"):
            return "x64"
        elif machine in ("i386", "i686", "x86"):
            return "x86"
        else:
            logger.warning(f"Unknown architecture: {machine}, defaulting to x64")
            return "x64"

    def check_nodejs(self, custom_path=None):
        """Check if Node.js is installed with configuration support."""
        nodejs_config = self.adobe_config.get("nodejs", {})

        # Use custom path from parameter or configuration
        if custom_path:
            configured_path = custom_path
        else:
            configured_path = nodejs_config.get("custom_path", "")

        node_cmd = "node"

        if configured_path:
            # Try configured custom path first
            custom_node = Path(configured_path) / "node.exe"
            if custom_node.exists():
                node_cmd = str(custom_node)
                logger.info(f"Using configured Node.js path: {node_cmd}")
            else:
                logger.error(f"Node.js not found at configured path: {configured_path}")
                return False

        try:
            timeout = nodejs_config.get("verification_timeout", 30)
            result = subprocess.run(
                [node_cmd, "--version"], capture_output=True, text=True, shell=True, timeout=timeout
            )
            if result.returncode == 0:
                version = result.stdout.strip()
                logger.info(f"Node.js found: {version}")

                # Save working path to configuration for future use
                if configured_path:
                    self.config.set("adobe_license_compiler.nodejs.custom_path", configured_path)

                return True
        except subprocess.TimeoutExpired:
            logger.error(f"Node.js version check timed out after {timeout} seconds")
        except FileNotFoundError:
            logger.debug("Node.js not found in PATH")
        except OSError as e:
            logger.error(f"Error executing Node.js: {e}")

        logger.warning("Node.js not found or not working")
        return False

    def install_nodejs(self):
        """Automatically install Node.js using multiple fallback methods."""
        logger.info("Attempting automatic Node.js installation...")

        # Try winget first
        if self._install_nodejs_winget():
            return True

        # Try chocolatey as fallback
        if self._install_nodejs_chocolatey():
            return True

        # Try direct download as final fallback
        if self._install_nodejs_direct():
            return True

        logger.error("All automatic installation methods failed")
        logger.error("Please manually install Node.js from https://nodejs.org")
        return False

    def _install_nodejs_winget(self):
        """Install Node.js using winget."""
        try:
            logger.info("Trying winget installation...")

            # Check if winget is available
            winget_check = subprocess.run(
                ["winget", "--version"], capture_output=True, text=True, shell=True
            )

            if winget_check.returncode != 0:
                logger.warning("winget not available")
                return False

            # Install Node.js using winget
            install_result = subprocess.run(
                [
                    "winget",
                    "install",
                    "OpenJS.NodeJS",
                    "--accept-package-agreements",
                    "--accept-source-agreements",
                ],
                capture_output=True,
                text=True,
                shell=True,
                timeout=300,
            )

            if install_result.returncode == 0:
                logger.info("Node.js installed via winget")
                return self._verify_nodejs_installation()
            else:
                logger.warning(f"winget install failed: {install_result.stderr}")
                return False

        except Exception as e:
            logger.warning(f"winget installation failed: {e}")
            return False

    def _install_nodejs_chocolatey(self):
        """Install Node.js using chocolatey."""
        try:
            logger.info("Trying chocolatey installation...")

            # Check if choco is available
            choco_check = subprocess.run(
                ["choco", "--version"], capture_output=True, text=True, shell=True
            )

            if choco_check.returncode != 0:
                logger.warning("chocolatey not available")
                return False

            # Install Node.js using chocolatey
            install_result = subprocess.run(
                ["choco", "install", "nodejs", "-y"],
                capture_output=True,
                text=True,
                shell=True,
                timeout=300,
            )

            if install_result.returncode == 0:
                logger.info("Node.js installed via chocolatey")
                return self._verify_nodejs_installation()
            else:
                logger.warning(f"chocolatey install failed: {install_result.stderr}")
                return False

        except Exception as e:
            logger.warning(f"chocolatey installation failed: {e}")
            return False

    def _install_nodejs_direct(self):
        """Install Node.js by downloading and running the installer with SHA256 validation."""
        try:
            logger.info("Trying direct download installation...")

            nodejs_config = self.adobe_config.get("nodejs", {})
            arch = self._get_architecture()
            arch_key = f"windows_{arch}"

            # Get download URL and expected hash from configuration
            download_urls = nodejs_config.get("download_urls", {})
            sha256_hashes = nodejs_config.get("sha256_hashes", {})

            if arch_key not in download_urls:
                logger.error(f"No Node.js download URL configured for architecture: {arch}")
                return False

            nodejs_url = download_urls[arch_key]
            expected_hash = sha256_hashes.get(arch_key, "")

            if not expected_hash and nodejs_config.get("verify_signatures", True):
                logger.error(f"No SHA256 hash configured for Node.js {arch} installer")
                return False

            with tempfile.NamedTemporaryFile(suffix=".msi", delete=False) as tmp_file:
                installer_path = tmp_file.name

            try:
                logger.info(f"Downloading Node.js installer from: {nodejs_url}")
                urllib.request.urlretrieve(nodejs_url, installer_path)

                # Verify SHA256 hash if configured
                if expected_hash and nodejs_config.get("verify_signatures", True):
                    logger.info("Verifying installer SHA256 hash...")
                    actual_hash = compute_file_hash(installer_path, "sha256")

                    if not actual_hash:
                        logger.error("Failed to compute installer hash")
                        return False

                    if actual_hash.lower() != expected_hash.lower():
                        logger.error(
                            f"SHA256 hash mismatch! Expected: {expected_hash}, Got: {actual_hash}"
                        )
                        return False

                    logger.info("SHA256 hash verification passed")

                # Run the installer silently
                logger.info("Running Node.js installer...")
                timeout = nodejs_config.get("installation_timeout", 600)
                install_result = subprocess.run(
                    ["msiexec", "/i", installer_path, "/quiet", "/norestart"],
                    capture_output=True,
                    text=True,
                    shell=True,
                    timeout=timeout,
                )

                if install_result.returncode == 0:
                    logger.info("Node.js installed via direct download")
                    return self._verify_nodejs_installation()
                else:
                    logger.warning(f"Direct install failed: {install_result.stderr}")
                    return False

            finally:
                # Cleanup installer
                try:
                    Path(installer_path).unlink()
                except OSError as e:
                    logger.debug(f"Failed to cleanup installer: {e}")

        except subprocess.TimeoutExpired:
            logger.error(f"Node.js installation timed out after {timeout} seconds")
            return False
        except urllib.error.URLError as e:
            logger.error(f"Failed to download Node.js installer: {e}")
            return False
        except Exception as e:
            logger.error(f"Direct installation failed: {e}")
            return False

    def _verify_nodejs_installation(self):
        """Verify Node.js installation after install attempt."""
        try:
            # Refresh environment variables
            subprocess.run(["refreshenv"], shell=True, capture_output=True)

            # Wait a moment for installation to complete
            time.sleep(2)

            # Verify installation
            verify_result = subprocess.run(
                ["node", "--version"], capture_output=True, text=True, shell=True
            )

            if verify_result.returncode == 0:
                version = verify_result.stdout.strip()
                logger.info(f"Node.js verified: {version}")
                return True
            else:
                logger.error("Node.js installation verification failed")
                return False

        except Exception as e:
            logger.error(f"Node.js verification failed: {e}")
            return False

    def install_npm_packages(self):
        """Install required npm packages for compilation."""
        packages = ["frida", "frida-compile", "pkg"]

        for package in packages:
            logger.info(f"Installing {package}...")
            try:
                # Check if already installed
                check_cmd = ["npm", "list", "-g", package, "--depth=0"]
                result = subprocess.run(check_cmd, capture_output=True, text=True, shell=True)

                if result.returncode != 0:
                    # Install globally
                    install_cmd = ["npm", "install", "-g", package]
                    result = subprocess.run(install_cmd, capture_output=True, text=True, shell=True)

                    if result.returncode != 0:
                        logger.error(f"Failed to install {package}: {result.stderr}")
                        return False
                    logger.info(f"Successfully installed {package}")
                else:
                    logger.info(f"{package} already installed")

            except Exception as e:
                logger.error(f"Error installing {package}: {e}")
                return False

        return True

    def create_wrapper_script(self):
        """Create Node.js wrapper that embeds and runs the Frida script."""
        # Get target processes from configuration
        target_processes = self.adobe_config.get(
            "target_processes",
            [
                "Photoshop.exe",
                "Illustrator.exe",
                "AfterFX.exe",
                "PremierePro.exe",
                "InDesign.exe",
                "Dreamweaver.exe",
                "Animate.exe",
                "Audition.exe",
                "Bridge.exe",
                "MediaEncoder.exe",
                "Prelude.exe",
                "LightroomCC.exe",
                "AcroRd32.exe",
                "Acrobat.exe",
                "AdobeARM.exe",
            ],
        )

        # Get monitoring configuration
        monitoring_config = self.adobe_config.get("monitoring", {})
        check_interval = monitoring_config.get("check_interval", 2000)
        log_injections = monitoring_config.get("log_injections", True)

        # Convert process list to JavaScript array format
        js_processes = json.dumps(target_processes)

        wrapper_content = f"""
const frida = require('frida');
const fs = require('fs');
const path = require('path');

// Embedded Frida script
const fridaScript = `
%SCRIPT_CONTENT%
`;

// Adobe process names to monitor (from configuration)
const adobeProcesses = {js_processes};

// Monitoring configuration
const checkInterval = {check_interval};
const logInjections = {str(log_injections).lower()};

// Track injected processes
const injected = new Set();

async function inject(processName) {{
    try {{
        if (injected.has(processName)) {{
            return;
        }}

        const session = await frida.attach(processName);
        const script = await session.createScript(fridaScript);

        script.message.connect((message) => {{
            if (message.type === 'send') {{
                if (logInjections) {{
                    console.log(`[${{processName}}] ${{message.payload}}`);
                }}
            }}
        }});

        await script.load();
        injected.add(processName);
        if (logInjections) {{
            console.log(`[+] Successfully injected into ${{processName}}`);
        }}

    }} catch (err) {{
        // Process not found or injection failed - silent fail
    }}
}}

async function findAdobeProcesses() {{
    try {{
        const processes = await frida.enumerateProcesses();
        const running = [];

        for (const proc of processes) {{
            if (adobeProcesses.some(name => proc.name.toLowerCase().includes(name.toLowerCase()))) {{
                if (!injected.has(proc.name)) {{
                    running.push(proc.name);
                }}
            }}
        }}

        return running;
    }} catch (err) {{
        return [];
    }}
}}

async function monitorLoop() {{
    console.log('[*] AdobeLicenseX Started - Monitoring for Adobe processes...');

    while (true) {{
        try {{
            const processes = await findAdobeProcesses();

            for (const proc of processes) {{
                await inject(proc);
            }}

        }} catch (err) {{
            // Continue monitoring even on error
        }}

        // Check at configured interval
        await new Promise(resolve => setTimeout(resolve, checkInterval));
    }}
}}

// Start monitoring
monitorLoop().catch(() => {{
    // Silent fail
}});

// Keep process running
process.stdin.resume();
"""

        # Read the actual Frida script content
        with open(self.bypass_script, "r", encoding="utf-8") as f:
            script_content = f.read()

        # Replace placeholder with actual script
        wrapper_content = wrapper_content.replace("%SCRIPT_CONTENT%", script_content)

        # Write wrapper to temp directory
        wrapper_path = self.temp_dir / "adobe_wrapper.js"
        with open(wrapper_path, "w", encoding="utf-8") as f:
            f.write(wrapper_content)

        return wrapper_path

    def create_package_json(self):
        """Create package.json for pkg compilation with configuration support."""
        compilation_config = self.adobe_config.get("compilation", {})
        deployment_config = self.adobe_config.get("deployment", {})

        # Get architecture and node version from configuration
        target_arch = compilation_config.get("target_architecture", "auto")
        if target_arch == "auto":
            arch = self._get_architecture()
        else:
            arch = target_arch

        node_version = compilation_config.get("node_version", "node18")
        compression = compilation_config.get("compression", "GZip")
        service_name = deployment_config.get("service_name", "AdobeLicenseX").lower()

        # Build pkg target string
        pkg_target = f"{node_version}-win-{arch}"

        package_json = {
            "name": service_name,
            "version": "1.0.0",
            "description": "Adobe License Manager",
            "main": "adobe_wrapper.js",
            "scripts": {"start": "node adobe_wrapper.js"},
            "dependencies": {"frida": "*"},
            "pkg": {"targets": [pkg_target], "outputPath": "dist", "compress": compression},
            "bin": "adobe_wrapper.js",
        }

        package_path = self.temp_dir / "package.json"
        with open(package_path, "w", encoding="utf-8") as f:
            json.dump(package_json, f, indent=2)

        return package_path

    def compile_to_exe(self):
        """Compile the wrapper script into standalone EXE using pkg."""
        try:
            # Create temp directory for compilation
            self.temp_dir = Path(tempfile.mkdtemp(prefix="adobe_compile_"))
            logger.info(f"Using temp directory: {self.temp_dir}")

            # Create wrapper script
            logger.info("Creating wrapper script...")
            wrapper_path = self.create_wrapper_script()

            # Create package.json
            logger.info("Creating package.json...")
            self.create_package_json()

            # Install local dependencies
            logger.info("Installing local dependencies...")
            npm_install = subprocess.run(
                ["npm", "install"],
                cwd=str(self.temp_dir),
                capture_output=True,
                text=True,
                shell=True,
            )

            if npm_install.returncode != 0:
                logger.error(f"npm install failed: {npm_install.stderr}")
                return None

            # Run pkg to create EXE
            logger.info("Compiling to EXE with pkg...")
            output_path = self.temp_dir / self.exe_name

            # Get compilation configuration
            compilation_config = self.adobe_config.get("compilation", {})
            timeout = compilation_config.get("timeout", 300)

            # Get target architecture
            target_arch = compilation_config.get("target_architecture", "auto")
            if target_arch == "auto":
                arch = self._get_architecture()
            else:
                arch = target_arch

            node_version = compilation_config.get("node_version", "node18")
            compression = compilation_config.get("compression", "GZip")
            pkg_target = f"{node_version}-win-{arch}"

            pkg_cmd = [
                "pkg",
                str(wrapper_path),
                "--target",
                pkg_target,
                "--output",
                str(output_path),
                "--compress",
                compression,
            ]

            result = subprocess.run(
                pkg_cmd,
                cwd=str(self.temp_dir),
                capture_output=True,
                text=True,
                shell=True,
                timeout=timeout,
            )

            if result.returncode != 0:
                logger.error(f"pkg compilation failed: {result.stderr}")
                return None

            if not output_path.exists():
                logger.error("EXE was not created")
                return None

            logger.info(f"Successfully created {self.exe_name}")
            return output_path

        except Exception as e:
            logger.error(f"Compilation failed: {e}")
            return None

    def deploy_to_startup(self, exe_path):
        """Deploy the compiled EXE to Windows startup folder."""
        try:
            # Ensure startup folder exists
            self.startup_folder.mkdir(parents=True, exist_ok=True)

            # Copy EXE to startup folder
            destination = self.startup_folder / self.exe_name
            shutil.copy2(exe_path, destination)

            logger.info(f"Deployed to startup: {destination}")

            # Set file attributes based on configuration
            deployment_config = self.adobe_config.get("deployment", {})
            if deployment_config.get("hidden_attributes", False):
                try:
                    import ctypes

                    FILE_ATTRIBUTE_HIDDEN = 0x02
                    FILE_ATTRIBUTE_SYSTEM = 0x04
                    ctypes.windll.kernel32.SetFileAttributesW(
                        str(destination), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM
                    )
                    logger.info("Applied hidden file attributes")
                except Exception as e:
                    logger.warning(f"Failed to set hidden attributes: {e}")

            return destination

        except Exception as e:
            logger.error(f"Failed to deploy to startup: {e}")
            return None

    def cleanup(self):
        """Clean up temporary files based on configuration."""
        compilation_config = self.adobe_config.get("compilation", {})
        should_cleanup = compilation_config.get("temp_cleanup", True)

        if should_cleanup and self.temp_dir and self.temp_dir.exists():
            try:
                shutil.rmtree(self.temp_dir)
                logger.info("Cleaned up temp files")
            except OSError as e:
                logger.warning(f"Failed to cleanup temp dir: {e}")
        elif not should_cleanup:
            logger.info(f"Temporary files preserved at: {self.temp_dir}")

    def compile_and_deploy(self):
        """Main method to compile and deploy AdobeLicenseX."""
        try:
            # Check prerequisites
            if not self.check_nodejs():
                return False, "Node.js is not installed"

            if not self.bypass_script.exists():
                return False, f"Bypass script not found: {self.bypass_script}"

            # Install required packages
            logger.info("Installing required npm packages...")
            if not self.install_npm_packages():
                return False, "Failed to install npm packages"

            # Compile to EXE
            logger.info("Compiling to EXE...")
            exe_path = self.compile_to_exe()

            if not exe_path:
                return False, "Failed to compile EXE"

            # Deploy to startup
            logger.info("Deploying to startup folder...")
            deployed_path = self.deploy_to_startup(exe_path)

            if not deployed_path:
                return False, "Failed to deploy to startup"

            # Cleanup
            self.cleanup()

            # Start the EXE
            logger.info("Starting AdobeLicenseX...")
            subprocess.Popen([str(deployed_path)], shell=True)

            return True, f"Successfully deployed to {deployed_path}"

        except Exception as e:
            self.cleanup()
            logger.error(f"Compile and deploy failed: {e}")
            return False, str(e)

    def uninstall(self):
        """Remove AdobeLicenseX from the system."""
        try:
            exe_path = self.startup_folder / self.exe_name
            removed_items = []

            # Try to terminate the process first
            try:
                subprocess.run(
                    ["taskkill", "/F", "/IM", self.exe_name], capture_output=True, shell=True
                )
                time.sleep(1)  # Give it time to terminate
            except (subprocess.SubprocessError, OSError) as e:
                logger.debug(f"Failed to terminate process {self.exe_name}: {e}")

            # Remove from startup folder
            if exe_path.exists():
                exe_path.unlink()
                removed_items.append("Startup EXE")
                logger.info(f"Removed from startup: {exe_path}")

            # Check and remove from other common locations
            other_locations = [
                Path(os.environ.get("PROGRAMDATA", ""))
                / "Microsoft"
                / "WindowsUpdate"
                / self.exe_name,
                Path(os.environ.get("TEMP", "")) / self.exe_name,
            ]

            for location in other_locations:
                if location.exists():
                    try:
                        location.unlink()
                        removed_items.append(str(location))
                        logger.info(f"Removed: {location}")
                    except OSError as e:
                        logger.debug(f"Failed to remove {location}: {e}")

            if removed_items:
                return True, f"Removed: {', '.join(removed_items)}"
            else:
                return True, "AdobeLicenseX was not installed"

        except Exception as e:
            logger.error(f"Uninstall failed: {e}")
            return False, str(e)

    def is_installed(self):
        """Check if AdobeLicenseX is installed."""
        exe_path = self.startup_folder / self.exe_name
        return exe_path.exists()

    def is_running(self):
        """Check if AdobeLicenseX process is running."""
        try:
            result = subprocess.run(
                ["tasklist", "/FI", f"IMAGENAME eq {self.exe_name}"],
                capture_output=True,
                text=True,
                shell=True,
                timeout=10,
            )
            return self.exe_name.lower() in result.stdout.lower()
        except (subprocess.SubprocessError, subprocess.TimeoutExpired, OSError) as e:
            logger.debug(f"Failed to check if {self.exe_name} is running: {e}")
            return False
