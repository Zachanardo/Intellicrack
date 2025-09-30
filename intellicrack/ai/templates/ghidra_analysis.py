"""This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

"""Ghidra analysis script template for Intellicrack AI.

Auto-generated Ghidra analysis script by Intellicrack AI
Target: {{target_binary}}
Analysis Type: {{analysis_type}}
Generated: {{timestamp}}
"""


# Script metadata
try:
    from intellicrack.utils.logger import logger
except ImportError:
    import logging

    logger = logging.getLogger(__name__)

SCRIPT_INFO = {
    "name": "{{script_name}}",
    "version": "1.0.0",
    "description": "{{description}}",
    "target": "{{target_binary}}",
    "analysis_type": "{{analysis_type}}",
    "generated": "{{timestamp}}",
}


def log(message):
    """Simple logging function."""
    print("[Intellicrack] " + str(message))


def analyze_license_functions():
    """Analyze functions that may contain license validation logic."""
    log("Starting license function analysis...")

    # Get current program
    try:
        program = getCurrentProgram()
    except NameError as e:
        logger.error("Name error in ghidra_analysis: %s", e)
        # getCurrentProgram is only available in Ghidra environment
        print("Error: This script must be run within Ghidra")
        return []
    listing = program.getListing()

    # License-related function name patterns
    license_patterns = ["license", "trial", "valid", "check", "auth", "serial", "key"]

    license_functions = []

    # Iterate through all functions
    function_iterator = listing.getFunctions(True)
    for function in function_iterator:
        func_name = function.getName().lower()

        # Check if function name contains license-related keywords
        for pattern in license_patterns:
            if pattern in func_name:
                license_functions.append(
                    {
                        "name": function.getName(),
                        "address": function.getEntryPoint(),
                        "size": function.getBody().getNumAddresses(),
                        "pattern_matched": pattern,
                    }
                )
                log("Found license function: {} at {}".format(function.getName(), function.getEntryPoint()))
                break

    return license_functions


def analyze_strings():
    """Analyze strings that may contain license-related data."""
    log("Starting string analysis...")

    try:
        program = getCurrentProgram()
    except NameError as e:
        logger.error("Name error in ghidra_analysis: %s", e)
        # getCurrentProgram is only available in Ghidra environment
        print("Error: This script must be run within Ghidra")
        return []
    program.getMemory()

    # License-related string patterns
    string_patterns = ["license", "trial", "expire", "valid", "serial", "key", "activation"]

    license_strings = []

    # Get all defined strings
    listing = program.getListing()
    data_iterator = listing.getDefinedData(True)

    for data in data_iterator:
        if data.hasStringValue():
            string_value = data.getValue()
            if string_value:
                string_lower = str(string_value).lower()

                for pattern in string_patterns:
                    if pattern in string_lower:
                        license_strings.append(
                            {
                                "value": str(string_value),
                                "address": data.getAddress(),
                                "pattern_matched": pattern,
                            }
                        )
                        log("Found license string: '{}' at {}".format(string_value, data.getAddress()))
                        break

    return license_strings


def analyze_imports():
    """Analyze imported functions that may be used for license validation."""
    log("Starting import analysis...")

    try:
        program = getCurrentProgram()
    except NameError as e:
        logger.error("Name error in ghidra_analysis: %s", e)
        # getCurrentProgram is only available in Ghidra environment
        print("Error: This script must be run within Ghidra")
        return []
    symbol_table = program.getSymbolTable()

    # Get external symbols (imports)
    external_symbols = symbol_table.getExternalSymbols()

    # License-related import patterns
    import_patterns = ["crypt", "hash", "time", "registry", "file", "network"]

    license_imports = []

    for symbol in external_symbols:
        symbol_name = symbol.getName().lower()

        for pattern in import_patterns:
            if pattern in symbol_name:
                license_imports.append(
                    {
                        "name": symbol.getName(),
                        "address": symbol.getAddress(),
                        "namespace": symbol.getParentNamespace().getName(),
                        "pattern_matched": pattern,
                    }
                )
                log("Found relevant import: {} from {}".format(symbol.getName(), symbol.getParentNamespace().getName()))
                break

    return license_imports


def find_crypto_functions():
    """Find cryptographic functions that may be used for license validation."""
    log("Searching for cryptographic functions...")

    try:
        program = getCurrentProgram()
    except NameError as e:
        logger.error("Name error in ghidra_analysis: %s", e)
        # getCurrentProgram is only available in Ghidra environment
        print("Error: This script must be run within Ghidra")
        return []
    listing = program.getListing()

    # Common crypto function patterns
    crypto_patterns = ["md5", "sha", "aes", "des", "rsa", "crc", "hash", "encrypt", "decrypt"]

    crypto_functions = []

    function_iterator = listing.getFunctions(True)
    for function in function_iterator:
        func_name = function.getName().lower()

        for pattern in crypto_patterns:
            if pattern in func_name:
                crypto_functions.append(
                    {
                        "name": function.getName(),
                        "address": function.getEntryPoint(),
                        "size": function.getBody().getNumAddresses(),
                        "crypto_type": pattern,
                    }
                )
                log("Found crypto function: {} at {}".format(function.getName(), function.getEntryPoint()))
                break

    return crypto_functions


def generate_bypass_recommendations(analysis_results):
    """Generate recommendations for bypassing license protections."""
    log("Generating bypass recommendations...")

    recommendations = []

    # Analyze license functions
    if analysis_results["license_functions"]:
        recommendations.append(
            {
                "type": "function_patching",
                "description": "Patch license validation functions to always return success",
                "targets": [f["name"] for f in analysis_results["license_functions"]],
                "method": "Replace function return with success value (1 or TRUE)",
            }
        )

    # Analyze license strings
    if analysis_results["license_strings"]:
        recommendations.append(
            {
                "type": "string_modification",
                "description": "Modify license validation strings",
                "targets": [s["value"] for s in analysis_results["license_strings"]],
                "method": "Replace validation strings with always-valid values",
            }
        )

    # Analyze crypto functions
    if analysis_results["crypto_functions"]:
        recommendations.append(
            {
                "type": "crypto_bypass",
                "description": "Bypass cryptographic license validation",
                "targets": [c["name"] for c in analysis_results["crypto_functions"]],
                "method": "Hook crypto functions to return expected values",
            }
        )

    return recommendations


def main():
    """Main analysis function."""
    log("Starting Intellicrack Ghidra analysis...")
    log("Script: {} v{}".format(SCRIPT_INFO["name"], SCRIPT_INFO["version"]))
    log("Target: {}".format(SCRIPT_INFO["target"]))

    # Perform analysis
    analysis_results = {
        "license_functions": analyze_license_functions(),
        "license_strings": analyze_strings(),
        "license_imports": analyze_imports(),
        "crypto_functions": find_crypto_functions(),
    }

    # Generate recommendations
    recommendations = generate_bypass_recommendations(analysis_results)

    # Print summary
    log("\n" + "=" * 60)
    log("ANALYSIS SUMMARY")
    log("=" * 60)
    log("License functions found: {}".format(len(analysis_results["license_functions"])))
    log("License strings found: {}".format(len(analysis_results["license_strings"])))
    log("Relevant imports found: {}".format(len(analysis_results["license_imports"])))
    log("Crypto functions found: {}".format(len(analysis_results["crypto_functions"])))
    log("Bypass recommendations: {}".format(len(recommendations)))

    # Print recommendations
    if recommendations:
        log("\nBYPASS RECOMMENDATIONS:")
        for i, rec in enumerate(recommendations, 1):
            log("{}. {}: {}".format(i, rec["type"], rec["description"]))
            log("   Method: {}".format(rec["method"]))
            log("   Targets: {}".format(", ".join(rec["targets"][:3]) + ("..." if len(rec["targets"]) > 3 else "")))

    log("\nAnalysis complete!")
    return analysis_results, recommendations


# Execute main analysis
if __name__ == "__main__":
    results, recommendations = main()
