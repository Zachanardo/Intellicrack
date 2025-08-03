/**
 * Quick String Dump
 *
 * @description Fast extraction of all strings with context
 * @author Intellicrack Team
 * @category Strings
 * @version 1.0
 * @tags strings,extraction,quick
 */

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import java.io.*;

public class QuickStringDump extends GhidraScript {

    @Override
    public void run() throws Exception {
        println("=== Quick String Dump ===");

        // Get output file
        File outputFile = askFile("Save strings to", "Save");

        try (PrintWriter writer = new PrintWriter(outputFile)) {
            writer.println("String Dump for: " + currentProgram.getName());
            writer.println("=" + "=".repeat(50));
            writer.println();

            int stringCount = 0;
            DataIterator dataIterator = currentProgram.getListing().getDefinedData(true);

            while (dataIterator.hasNext()) {
                Data data = dataIterator.next();

                if (data.hasStringValue()) {
                    String value = data.getDefaultValueRepresentation();

                    // Filter out very short strings
                    if (value.length() > 3) {
                        writer.println(String.format("0x%08X: %s",
                            data.getAddress().getOffset(), value));
                        stringCount++;
                    }
                }
            }

            writer.println();
            writer.println("Total strings extracted: " + stringCount);

            println("Extracted " + stringCount + " strings to " + outputFile.getAbsolutePath());
        }
    }
}
