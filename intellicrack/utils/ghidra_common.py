"""Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""

import logging
import os
import subprocess
from typing import Any

logger = logging.getLogger(__name__)


def run_ghidra_plugin(ghidra_path: str,
                     project_dir: str,
                     project_name: str,
                     binary_path: str,
                     script_dir: str,
                     script_name: str,
                     app: Any = None,
                     overwrite: bool = True,
                     timeout: int = 300) -> tuple[int, str, str]:
    """Run a Ghidra plugin script on a binary.

    Args:
        ghidra_path: Path to Ghidra executable
        project_dir: Directory for Ghidra project
        project_name: Name of the Ghidra project
        binary_path: Path to binary to analyze
        script_dir: Directory containing the script
        script_name: Name of the script to run
        app: Application instance for logging
        overwrite: Whether to overwrite existing project
        timeout: Timeout in seconds

    Returns:
        Tuple of (return_code, stdout, stderr)

    """
    try:
        # Validate inputs
        if not os.path.exists(ghidra_path):
            error_msg = f"Ghidra not found at: {ghidra_path}"
            logger.error(error_msg)
            return 1, "", error_msg

        if not os.path.exists(binary_path):
            error_msg = f"Binary not found at: {binary_path}"
            logger.error(error_msg)
            return 1, "", error_msg

        script_path = os.path.join(script_dir, script_name)
        if not os.path.exists(script_path):
            error_msg = f"Script not found at: {script_path}"
            logger.error(error_msg)
            return 1, "", error_msg

        # Create project directory
        os.makedirs(project_dir, exist_ok=True)

        # Build Ghidra command
        command = _build_ghidra_command(
            ghidra_path=ghidra_path,
            project_dir=project_dir,
            project_name=project_name,
            binary_path=binary_path,
            script_path=script_path,
            overwrite=overwrite,
        )

        if app:
            app.update_output.emit(f"[Ghidra] Running command: {' '.join(command)}")

        logger.info(f"Running Ghidra command: {' '.join(command)}")

        # Execute Ghidra
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=project_dir,
        )

        try:
            stdout, stderr = process.communicate(timeout=timeout)
            return_code = process.returncode

            logger.info(f"Ghidra execution completed with return code: {return_code}")

            return return_code, stdout, stderr

        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
            error_msg = f"Ghidra execution timed out after {timeout} seconds"
            logger.warning(error_msg)
            return 124, stdout, error_msg  # 124 is standard timeout exit code

    except Exception as e:
        error_msg = f"Ghidra execution failed: {e}"
        logger.error(error_msg)
        return 1, "", error_msg


def _build_ghidra_command(ghidra_path: str,
                         project_dir: str,
                         project_name: str,
                         binary_path: str,
                         script_path: str,
                         overwrite: bool = True) -> list[str]:
    """Build the Ghidra command line."""
    command = [ghidra_path]

    # Add project location
    command.extend([project_dir, project_name])

    # Import binary
    command.extend(["-import", binary_path])

    # Overwrite if requested
    if overwrite:
        command.append("-overwrite")

    # Run script
    command.extend(["-scriptPath", os.path.dirname(script_path)])
    command.extend(["-postScript", os.path.basename(script_path)])

    # Run in headless mode
    command.append("-headless")

    return command


def create_ghidra_analysis_script(analysis_type: str = "basic") -> str:
    """Create a Ghidra analysis script.

    Args:
        analysis_type: Type of analysis to perform

    Returns:
        Script content as string

    """
    if analysis_type == "license_analysis":
        return _create_license_analysis_script()
    if analysis_type == "function_analysis":
        return _create_function_analysis_script()
    if analysis_type == "string_analysis":
        return _create_string_analysis_script()
    return _create_basic_analysis_script()


def _create_basic_analysis_script() -> str:
    """Create a basic Ghidra analysis script."""
    return """//Basic binary analysis script for Ghidra
//@author Intellicrack
//@category Analysis
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.*;

public class BasicAnalysis extends GhidraScript {

    @Override
    public void run() throws Exception {

        println("=== Intellicrack Basic Analysis ===");

        // Get program info
        Program program = getCurrentProgram();
        println("Program: " + program.getName());
        println("Language: " + program.getLanguageID());
        println("Entry Point: " + program.getImageBase().toString());

        // Analyze functions
        analyzeFunctions();

        // Analyze strings
        analyzeStrings();

        // Analyze imports
        analyzeImports();

        println("=== Analysis Complete ===");
    }

    private void analyzeFunctions() {
        println("\\n--- Function Analysis ---");
        FunctionManager funcMgr = getCurrentProgram().getFunctionManager();
        int functionCount = funcMgr.getFunctionCount();
        println("Total Functions: " + functionCount);

        // List first 10 functions
        int count = 0;
        FunctionIterator iter = funcMgr.getFunctions(true);
        while (iter.hasNext() && count < 10) {
            Function func = iter.next();
            println("Function: " + func.getName() + " @ " + func.getEntryPoint());
            count++;
        }

        if (functionCount > 10) {
            println("... and " + (functionCount - 10) + " more functions");
        }
    }

    private void analyzeStrings() {
        println("\\n--- String Analysis ---");
        Listing listing = getCurrentProgram().getListing();
        Memory memory = getCurrentProgram().getMemory();

        int stringCount = 0;
        MemoryBlock[] blocks = memory.getBlocks();

        for (MemoryBlock block : blocks) {
            if (block.isRead() && !block.isWrite()) { // Likely read-only data
                DataIterator dataIter = listing.getDefinedData(block.getStart(), true);
                while (dataIter.hasNext()) {
                    Data data = dataIter.next();
                    if (data.hasStringValue()) {
                        stringCount++;
                        if (stringCount <= 10) {
                            String stringValue = data.getDefaultValueRepresentation();
                            println("String: " + stringValue + " @ " + data.getAddress());
                        }
                    }
                }
            }
        }

        println("Total Strings Found: " + stringCount);
    }

    private void analyzeImports() {
        println("\\n--- Import Analysis ---");
        SymbolTable symbolTable = getCurrentProgram().getSymbolTable();
        SymbolIterator iter = symbolTable.getExternalSymbols();

        int importCount = 0;
        while (iter.hasNext()) {
            Symbol symbol = iter.next();
            importCount++;
            if (importCount <= 10) {
                println("Import: " + symbol.getName() + " from " +
                       symbol.getParentNamespace().getName());
            }
        }

        if (importCount > 10) {
            println("... and " + (importCount - 10) + " more imports");
        }

        println("Total Imports: " + importCount);
    }
}"""


def _create_license_analysis_script() -> str:
    """Create a license-focused analysis script."""
    return """//License validation analysis script for Ghidra
//@author Intellicrack
//@category License
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.address.*;
import java.util.*;

public class LicenseAnalysis extends GhidraScript {

    @Override
    public void run() throws Exception {

        println("=== Intellicrack License Analysis ===");

        // Search for license-related functions
        findLicenseFunctions();

        // Search for license-related strings
        findLicenseStrings();

        // Search for crypto functions
        findCryptoFunctions();

        // Search for time-related functions
        findTimeFunctions();

        println("=== License Analysis Complete ===");
    }

    private void findLicenseFunctions() {
        println("\\n--- License Function Analysis ---");
        FunctionManager funcMgr = getCurrentProgram().getFunctionManager();
        String[] licenseKeywords = {"license", "valid", "check", "verify", "auth", "trial", "expire", "register"};

        int foundCount = 0;
        FunctionIterator iter = funcMgr.getFunctions(true);
        while (iter.hasNext()) {
            Function func = iter.next();
            String funcName = func.getName().toLowerCase();

            for (String keyword : licenseKeywords) {
                if (funcName.contains(keyword)) {
                    println("License Function: " + func.getName() + " @ " + func.getEntryPoint());
                    foundCount++;
                    break;
                }
            }
        }

        println("License-related functions found: " + foundCount);
    }

    private void findLicenseStrings() {
        println("\\n--- License String Analysis ---");
        Listing listing = getCurrentProgram().getListing();
        Memory memory = getCurrentProgram().getMemory();
        String[] licenseKeywords = {"license", "trial", "expire", "valid", "invalid", "key", "serial", "activate"};

        int foundCount = 0;
        MemoryBlock[] blocks = memory.getBlocks();

        for (MemoryBlock block : blocks) {
            if (block.isRead()) {
                DataIterator dataIter = listing.getDefinedData(block.getStart(), true);
                while (dataIter.hasNext()) {
                    Data data = dataIter.next();
                    if (data.hasStringValue()) {
                        String stringValue = data.getDefaultValueRepresentation().toLowerCase();

                        for (String keyword : licenseKeywords) {
                            if (stringValue.contains(keyword)) {
                                println("License String: " + data.getDefaultValueRepresentation() +
                                       " @ " + data.getAddress());
                                foundCount++;
                                break;
                            }
                        }
                    }
                }
            }
        }

        println("License-related strings found: " + foundCount);
    }

    private void findCryptoFunctions() {
        println("\\n--- Crypto Function Analysis ---");
        SymbolTable symbolTable = getCurrentProgram().getSymbolTable();
        String[] cryptoKeywords = {"crypt", "hash", "md5", "sha", "aes", "des", "rsa", "encrypt", "decrypt"};

        int foundCount = 0;
        SymbolIterator iter = symbolTable.getAllSymbols(true);
        while (iter.hasNext()) {
            Symbol symbol = iter.next();
            String symbolName = symbol.getName().toLowerCase();

            for (String keyword : cryptoKeywords) {
                if (symbolName.contains(keyword)) {
                    println("Crypto Symbol: " + symbol.getName() + " @ " + symbol.getAddress());
                    foundCount++;
                    break;
                }
            }
        }

        println("Crypto-related symbols found: " + foundCount);
    }

    private void findTimeFunctions() {
        println("\\n--- Time Function Analysis ---");
        SymbolTable symbolTable = getCurrentProgram().getSymbolTable();
        String[] timeKeywords = {"time", "date", "tick", "clock", "timer", "stamp"};

        int foundCount = 0;
        SymbolIterator iter = symbolTable.getAllSymbols(true);
        while (iter.hasNext()) {
            Symbol symbol = iter.next();
            String symbolName = symbol.getName().toLowerCase();

            for (String keyword : timeKeywords) {
                if (symbolName.contains(keyword)) {
                    println("Time Symbol: " + symbol.getName() + " @ " + symbol.getAddress());
                    foundCount++;
                    break;
                }
            }
        }

        println("Time-related symbols found: " + foundCount);
    }
}"""


def _create_function_analysis_script() -> str:
    """Create a function analysis script."""
    return """//Function analysis script for Ghidra
//@author Intellicrack
//@category Analysis
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.address.*;

public class FunctionAnalysis extends GhidraScript {

    @Override
    public void run() throws Exception {

        println("=== Intellicrack Function Analysis ===");

        analyzeFunctionComplexity();
        analyzeCallGraph();
        findInterestingFunctions();

        println("=== Function Analysis Complete ===");
    }

    private void analyzeFunctionComplexity() {
        println("\\n--- Function Complexity Analysis ---");
        FunctionManager funcMgr = getCurrentProgram().getFunctionManager();

        int simple = 0, moderate = 0, complex = 0;

        FunctionIterator iter = funcMgr.getFunctions(true);
        while (iter.hasNext()) {
            Function func = iter.next();
            long size = func.getBody().getNumAddresses();

            if (size < 50) {
                simple++;
            } else if (size < 200) {
                moderate++;
            } else {
                complex++;
                println("Complex Function: " + func.getName() + " (size: " + size + ") @ " + func.getEntryPoint());
            }
        }

        println("Simple functions (< 50 instructions): " + simple);
        println("Moderate functions (50-200 instructions): " + moderate);
        println("Complex functions (> 200 instructions): " + complex);
    }

    private void analyzeCallGraph() {
        println("\\n--- Call Graph Analysis ---");
        FunctionManager funcMgr = getCurrentProgram().getFunctionManager();

        Function mainFunc = getMainFunction();
        if (mainFunc != null) {
            println("Main function found: " + mainFunc.getName() + " @ " + mainFunc.getEntryPoint());
            analyzeCallTree(mainFunc, 1, 3); // Analyze 3 levels deep
        }
    }

    private Function getMainFunction() {
        FunctionManager funcMgr = getCurrentProgram().getFunctionManager();

        // Try to find main function
        Function main = funcMgr.getFunction("main");
        if (main != null) return main;

        main = funcMgr.getFunction("_main");
        if (main != null) return main;

        main = funcMgr.getFunction("WinMain");
        if (main != null) return main;

        // Return entry point function
        AddressSetView entries = getCurrentProgram().getSymbolTable().getExternalEntryPointIterator();
        if (!entries.isEmpty()) {
            Address entryAddr = entries.getMinAddress();
            return funcMgr.getFunctionAt(entryAddr);
        }

        return null;
    }

    private void analyzeCallTree(Function func, int level, int maxLevel) {
        if (level > maxLevel || func == null) return;

        String indent = "  ".repeat(level);
        println(indent + "Level " + level + ": " + func.getName());

        Set<Function> calledFunctions = func.getCalledFunctions(null);
        for (Function calledFunc : calledFunctions) {
            if (level < maxLevel) {
                analyzeCallTree(calledFunc, level + 1, maxLevel);
            }
        }
    }

    private void findInterestingFunctions() {
        println("\\n--- Interesting Functions ---");
        FunctionManager funcMgr = getCurrentProgram().getFunctionManager();
        String[] interestingKeywords = {"decrypt", "check", "valid", "auth", "parse", "verify"};

        FunctionIterator iter = funcMgr.getFunctions(true);
        while (iter.hasNext()) {
            Function func = iter.next();
            String funcName = func.getName().toLowerCase();

            for (String keyword : interestingKeywords) {
                if (funcName.contains(keyword)) {
                    println("Interesting: " + func.getName() + " @ " + func.getEntryPoint());
                    break;
                }
            }
        }
    }
}"""


def _create_string_analysis_script() -> str:
    """Create a string analysis script."""
    return """//String analysis script for Ghidra
//@author Intellicrack
//@category Analysis
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.address.*;
import java.util.*;
import java.util.regex.*;

public class StringAnalysis extends GhidraScript {

    @Override
    public void run() throws Exception {

        println("=== Intellicrack String Analysis ===");

        analyzeAllStrings();
        findUrls();
        findFilePaths();
        findErrorMessages();

        println("=== String Analysis Complete ===");
    }

    private void analyzeAllStrings() {
        println("\\n--- All Strings Analysis ---");
        Listing listing = getCurrentProgram().getListing();
        Memory memory = getCurrentProgram().getMemory();

        Map<String, Integer> stringCategories = new HashMap<>();
        stringCategories.put("URLs", 0);
        stringCategories.put("File Paths", 0);
        stringCategories.put("Error Messages", 0);
        stringCategories.put("Registry Keys", 0);
        stringCategories.put("Crypto Related", 0);
        stringCategories.put("Other", 0);

        MemoryBlock[] blocks = memory.getBlocks();
        for (MemoryBlock block : blocks) {
            if (block.isRead()) {
                DataIterator dataIter = listing.getDefinedData(block.getStart(), true);
                while (dataIter.hasNext()) {
                    Data data = dataIter.next();
                    if (data.hasStringValue()) {
                        String stringValue = data.getDefaultValueRepresentation();
                        categorizeString(stringValue, stringCategories);
                    }
                }
            }
        }

        for (Map.Entry<String, Integer> entry : stringCategories.entrySet()) {
            println(entry.getKey() + ": " + entry.getValue());
        }
    }

    private void categorizeString(String str, Map<String, Integer> categories) {
        String lowerStr = str.toLowerCase();

        if (lowerStr.contains("http") || lowerStr.contains("www.") || lowerStr.contains(".com")) {
            categories.put("URLs", categories.get("URLs") + 1);
        } else if (lowerStr.contains("\\\\") || lowerStr.contains("c:") || lowerStr.contains(".exe") || lowerStr.contains(".dll")) {
            categories.put("File Paths", categories.get("File Paths") + 1);
        } else if (lowerStr.contains("error") || lowerStr.contains("fail") || lowerStr.contains("invalid")) {
            categories.put("Error Messages", categories.get("Error Messages") + 1);
        } else if (lowerStr.contains("hkey_") || lowerStr.contains("software\\\\")) {
            categories.put("Registry Keys", categories.get("Registry Keys") + 1);
        } else if (lowerStr.contains("crypt") || lowerStr.contains("hash") || lowerStr.contains("key")) {
            categories.put("Crypto Related", categories.get("Crypto Related") + 1);
        } else {
            categories.put("Other", categories.get("Other") + 1);
        }
    }

    private void findUrls() {
        println("\\n--- URL Analysis ---");
        Listing listing = getCurrentProgram().getListing();
        Memory memory = getCurrentProgram().getMemory();
        Pattern urlPattern = Pattern.compile("https?://[\\\\w.-]+(?:\\\\.[\\\\w.-]+)+[\\\\w\\\\-\\\\._~:/?#[\\\\]@!\\\\$&'()*+,;=.]*");

        int urlCount = 0;
        MemoryBlock[] blocks = memory.getBlocks();
        for (MemoryBlock block : blocks) {
            if (block.isRead()) {
                DataIterator dataIter = listing.getDefinedData(block.getStart(), true);
                while (dataIter.hasNext()) {
                    Data data = dataIter.next();
                    if (data.hasStringValue()) {
                        String stringValue = data.getDefaultValueRepresentation();
                        Matcher matcher = urlPattern.matcher(stringValue);
                        if (matcher.find()) {
                            println("URL Found: " + stringValue + " @ " + data.getAddress());
                            urlCount++;
                        }
                    }
                }
            }
        }

        println("Total URLs found: " + urlCount);
    }

    private void findFilePaths() {
        println("\\n--- File Path Analysis ---");
        Listing listing = getCurrentProgram().getListing();
        Memory memory = getCurrentProgram().getMemory();

        int pathCount = 0;
        MemoryBlock[] blocks = memory.getBlocks();
        for (MemoryBlock block : blocks) {
            if (block.isRead()) {
                DataIterator dataIter = listing.getDefinedData(block.getStart(), true);
                while (dataIter.hasNext()) {
                    Data data = dataIter.next();
                    if (data.hasStringValue()) {
                        String stringValue = data.getDefaultValueRepresentation();
                        if (isFilePath(stringValue)) {
                            println("File Path: " + stringValue + " @ " + data.getAddress());
                            pathCount++;
                        }
                    }
                }
            }
        }

        println("Total file paths found: " + pathCount);
    }

    private boolean isFilePath(String str) {
        return str.contains("\\\\") || str.contains("/") ||
               str.matches(".*\\\\.[a-zA-Z]{2,4}$") ||
               str.startsWith("C:") || str.startsWith("/");
    }

    private void findErrorMessages() {
        println("\\n--- Error Message Analysis ---");
        Listing listing = getCurrentProgram().getListing();
        Memory memory = getCurrentProgram().getMemory();
        String[] errorKeywords = {"error", "fail", "invalid", "corrupt", "cannot", "unable", "denied"};

        int errorCount = 0;
        MemoryBlock[] blocks = memory.getBlocks();
        for (MemoryBlock block : blocks) {
            if (block.isRead()) {
                DataIterator dataIter = listing.getDefinedData(block.getStart(), true);
                while (dataIter.hasNext()) {
                    Data data = dataIter.next();
                    if (data.hasStringValue()) {
                        String stringValue = data.getDefaultValueRepresentation().toLowerCase();

                        for (String keyword : errorKeywords) {
                            if (stringValue.contains(keyword)) {
                                println("Error Message: " + data.getDefaultValueRepresentation() +
                                       " @ " + data.getAddress());
                                errorCount++;
                                break;
                            }
                        }
                    }
                }
            }
        }

        println("Total error messages found: " + errorCount);
    }
}"""


def save_ghidra_script(script_content: str, script_name: str, output_dir: str) -> str:
    """Save a Ghidra script to file.

    Args:
        script_content: Content of the script
        script_name: Name of the script file
        output_dir: Directory to save the script

    Returns:
        Path to the saved script file

    """
    try:
        os.makedirs(output_dir, exist_ok=True)

        # Ensure .java extension
        if not script_name.endswith(".java"):
            script_name += ".java"

        script_path = os.path.join(output_dir, script_name)

        with open(script_path, "w", encoding="utf-8") as f:
            f.write(script_content)

        logger.info(f"Ghidra script saved to: {script_path}")
        return script_path

    except Exception as e:
        logger.error(f"Failed to save Ghidra script: {e}")
        raise


def get_ghidra_project_info(project_dir: str, project_name: str) -> dict[str, Any]:
    """Get information about a Ghidra project.

    Args:
        project_dir: Directory containing the project
        project_name: Name of the project

    Returns:
        Dictionary with project information

    """
    info = {
        "exists": False,
        "project_dir": project_dir,
        "project_name": project_name,
        "files": [],
        "size": 0,
    }

    try:
        project_path = os.path.join(project_dir, f"{project_name}.gpr")

        if os.path.exists(project_path):
            info["exists"] = True
            info["project_file"] = project_path
            info["size"] = os.path.getsize(project_path)
            info["modified"] = os.path.getmtime(project_path)

            # List project files
            project_files = []
            for file in os.listdir(project_dir):
                if file.startswith(project_name):
                    project_files.append(file)
            info["files"] = project_files

    except Exception as e:
        logger.debug(f"Failed to get project info: {e}")

    return info


def cleanup_ghidra_project(project_dir: str, project_name: str) -> bool:
    """Clean up a Ghidra project directory.

    Args:
        project_dir: Directory containing the project
        project_name: Name of the project

    Returns:
        True if cleanup was successful

    """
    try:
        if not os.path.exists(project_dir):
            return True

        # Remove project files
        for file in os.listdir(project_dir):
            if file.startswith(project_name):
                file_path = os.path.join(project_dir, file)
                if os.path.isfile(file_path):
                    os.remove(file_path)
                elif os.path.isdir(file_path):
                    import shutil
                    shutil.rmtree(file_path)

        # Remove directory if empty
        if not os.listdir(project_dir):
            os.rmdir(project_dir)

        logger.info(f"Cleaned up Ghidra project: {project_name}")
        return True

    except Exception as e:
        logger.error(f"Failed to cleanup Ghidra project: {e}")
        return False


# Export commonly used functions
__all__ = [
    "cleanup_ghidra_project",
    "create_ghidra_analysis_script",
    "get_ghidra_project_info",
    "run_ghidra_plugin",
    "save_ghidra_script",
]
