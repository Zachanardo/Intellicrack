
//Sample Ghidra Script for Intellicrack
//@category SecurityResearch

import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.*;
import ghidra.program.model.listing.*;

public class LicensePatternScanner extends GhidraScript {

    @Override
    public void run() throws Exception {
        println("License Pattern Scanner starting...");

        // Search for license-related symbols
        SymbolTable symbolTable = currentProgram.getSymbolTable();
        SymbolIterator symbols = symbolTable.getAllSymbols(true);

        int licenseRelatedCount = 0;

        for (Symbol symbol : symbols) {
            String name = symbol.getName().toLowerCase();
            if (name.contains("licens") || name.contains("serial") ||
                name.contains("activ") || name.contains("valid")) {
                println("Found license-related symbol: " + symbol.getName() +
                       " at " + symbol.getAddress());
                licenseRelatedCount++;
            }
        }

        println("License Pattern Scanner completed. Found " + licenseRelatedCount +
               " license-related symbols.");
    }
}
