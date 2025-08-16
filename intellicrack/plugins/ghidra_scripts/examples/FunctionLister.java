/**
 * Function Lister Example
 *
 * @description Lists all functions in the program with basic information
 * @author Intellicrack Examples
 * @category Examples
 * @version 1.0
 * @tags example,functions,beginner
 */

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;

public class FunctionLister extends GhidraScript {

    @Override
    public void run() throws Exception {
        println("=== Function Lister Example ===");
        println("This script lists all functions in the program.\n");

        // Get the function manager
        FunctionManager functionManager = currentProgram.getFunctionManager();

        // Get iterator for all functions
        FunctionIterator functions = functionManager.getFunctions(true);

        int count = 0;
        int maxFunctions = 25;  // Limit for example

        println("Functions found:");
        println("-" + "-".repeat(60));

        while (functions.hasNext() && count < maxFunctions) {
            Function function = functions.next();

            // Get function information
            String name = function.getName();
            long address = function.getEntryPoint().getOffset();
            int paramCount = function.getParameterCount();
            long size = function.getBody().getNumAddresses();

            // Print function details
            println(String.format("0x%08X | %-30s | Params: %d | Size: %d bytes",
                address, name, paramCount, size));

            count++;
        }

        println("-" + "-".repeat(60));
        println("Total functions shown: " + count);

        // Count total functions
        int totalFunctions = functionManager.getFunctionCount();
        println("Total functions in program: " + totalFunctions);

        println("\nExtend this example to:");
        println("- Filter by function name patterns");
        println("- Analyze function complexity");
        println("- Find functions with specific characteristics");
    }
}
