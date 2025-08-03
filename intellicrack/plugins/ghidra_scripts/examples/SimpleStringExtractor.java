/**
 * Simple String Extractor Example
 *
 * @description Basic example showing how to extract strings from a binary
 * @author Intellicrack Examples
 * @category Examples
 * @version 1.0
 * @tags example,strings,beginner
 */

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;

public class SimpleStringExtractor extends GhidraScript {

    @Override
    public void run() throws Exception {
        println("=== Simple String Extractor Example ===");
        println("This script demonstrates basic string extraction.\n");

        // Get the data iterator
        DataIterator dataIterator = currentProgram.getListing().getDefinedData(true);

        int count = 0;
        int maxStrings = 20;  // Limit output for example

        // Iterate through all defined data
        while (dataIterator.hasNext() && count < maxStrings) {
            Data data = dataIterator.next();

            // Check if this data has a string value
            if (data.hasStringValue()) {
                String value = data.getDefaultValueRepresentation();

                // Only print strings longer than 4 characters
                if (value.length() > 4) {
                    println(String.format("String at 0x%08X: %s",
                        data.getAddress().getOffset(), value));
                    count++;
                }
            }
        }

        println("\nFound " + count + " strings (showing first " + maxStrings + ")");
        println("\nThis is a basic example - enhance it to:");
        println("- Filter by string content");
        println("- Export to file");
        println("- Search for specific patterns");
    }
}
