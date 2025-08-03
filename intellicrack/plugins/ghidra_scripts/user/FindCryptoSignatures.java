/**
 * Find Cryptographic Signatures in Binary
 *
 * @description Scans for cryptographic algorithm signatures and constants
 * @author Intellicrack Team
 * @category Cryptography
 * @version 1.0
 * @tags crypto,signatures,aes,rsa,security
 */

import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import java.util.*;

public class FindCryptoSignatures extends GhidraScript {

    // Common crypto constants
    private static final long[] AES_SBOX_PATTERNS = {
        0x637c777bL, 0xf26b6fc5L, 0x3001672bL, 0xfed7ab76L
    };

    private static final long[] SHA256_CONSTANTS = {
        0x428a2f98L, 0x71374491L, 0xb5c0fbcfL, 0xe9b5dba5L
    };

    private static final long[] MD5_CONSTANTS = {
        0xd76aa478L, 0xe8c7b756L, 0x242070dbL, 0xc1bdceeeL
    };

    @Override
    public void run() throws Exception {
        println("=== Cryptographic Signature Scanner ===");

        Memory memory = currentProgram.getMemory();
        int cryptoSignaturesFound = 0;

        // Search for AES S-box
        println("\nSearching for AES S-box patterns...");
        for (MemoryBlock block : memory.getBlocks()) {
            if (!block.isExecute()) continue;

            Address start = block.getStart();
            Address end = block.getEnd();

            // Search for AES patterns
            for (long pattern : AES_SBOX_PATTERNS) {
                Address[] found = findBytes(start, end, intToBytes(pattern), 100);
                if (found.length > 0) {
                    println("  [+] Found AES S-box signature at: " + found[0]);
                    createBookmark(found[0], "Crypto", "AES S-box detected");
                    cryptoSignaturesFound++;
                    break;
                }
            }
        }

        // Search for SHA-256 constants
        println("\nSearching for SHA-256 constants...");
        for (MemoryBlock block : memory.getBlocks()) {
            if (!block.isExecute()) continue;

            Address start = block.getStart();
            Address end = block.getEnd();

            for (long pattern : SHA256_CONSTANTS) {
                Address[] found = findBytes(start, end, intToBytes(pattern), 100);
                if (found.length > 0) {
                    println("  [+] Found SHA-256 constant at: " + found[0]);
                    createBookmark(found[0], "Crypto", "SHA-256 constant detected");
                    cryptoSignaturesFound++;
                    break;
                }
            }
        }

        // Search for MD5 constants
        println("\nSearching for MD5 constants...");
        for (MemoryBlock block : memory.getBlocks()) {
            if (!block.isExecute()) continue;

            Address start = block.getStart();
            Address end = block.getEnd();

            for (long pattern : MD5_CONSTANTS) {
                Address[] found = findBytes(start, end, intToBytes(pattern), 100);
                if (found.length > 0) {
                    println("  [+] Found MD5 constant at: " + found[0]);
                    createBookmark(found[0], "Crypto", "MD5 constant detected");
                    cryptoSignaturesFound++;
                    break;
                }
            }
        }

        // Search for RSA-related patterns
        println("\nSearching for RSA key patterns...");
        searchForRSAPatterns();

        // Summary
        println("\n=== Summary ===");
        println("Total cryptographic signatures found: " + cryptoSignaturesFound);

        if (cryptoSignaturesFound > 0) {
            println("\nThe binary appears to use cryptographic functions.");
            println("Check bookmarks for detailed locations.");
        } else {
            println("\nNo obvious cryptographic signatures found.");
            println("The binary may use custom crypto or obfuscation.");
        }
    }

    private void searchForRSAPatterns() throws Exception {
        // Look for common RSA key headers
        String[] rsaPatterns = {
            "-----BEGIN RSA",
            "-----BEGIN PUBLIC KEY",
            "MIIBIjANBgkq", // Common RSA public key start
            "MIICdgIBADANBgkq" // Common RSA private key start
        };

        for (String pattern : rsaPatterns) {
            Address[] found = findBytes(currentProgram.getMinAddress(),
                                       pattern.getBytes(), 10);
            for (Address addr : found) {
                println("  [+] Found potential RSA key at: " + addr);
                createBookmark(addr, "Crypto", "Potential RSA key");
            }
        }
    }

    private byte[] intToBytes(long value) {
        return new byte[] {
            (byte)(value >> 24),
            (byte)(value >> 16),
            (byte)(value >> 8),
            (byte)value
        };
    }
}
