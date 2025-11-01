import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.nio.charset.*;
import java.util.*;

public class StringDecryptionAutomator extends GhidraScript {

  private Map<Address, EncryptedString> encryptedStrings = new HashMap<>();
  private Map<Address, DecryptionRoutine> decryptionRoutines = new HashMap<>();
  private Map<String, Integer> decryptionAlgorithms = new HashMap<>();
  private int stringsDecrypted = 0;
  private int decryptionFunctionsFound = 0;

  @Override
  public void run() throws Exception {
    println("=== String Decryption Automator ===");
    println("Analyzing: " + currentProgram.getName());
    println();

    println("[Phase 1] Identifying decryption routines...");
    identifyDecryptionRoutines();

    println("\n[Phase 2] Locating encrypted strings...");
    locateEncryptedStrings();

    println("\n[Phase 3] Attempting automated decryption...");
    attemptAutomatedDecryption();

    println("\n=== Decryption Summary ===");
    println("Decryption functions found: " + decryptionFunctionsFound);
    println("Encrypted strings located: " + encryptedStrings.size());
    println("Strings successfully decrypted: " + stringsDecrypted);

    if (!decryptionAlgorithms.isEmpty()) {
      println("\nDecryption algorithms detected:");
      for (Map.Entry<String, Integer> entry : decryptionAlgorithms.entrySet()) {
        println("  " + entry.getKey() + ": " + entry.getValue() + " instances");
      }
    }

    if (stringsDecrypted > 0) {
      println("\n[Phase 4] Generating decrypted strings report...");
      generateDecryptionReport();
    }
  }

  private void identifyDecryptionRoutines() {
    FunctionManager functionManager = currentProgram.getFunctionManager();
    FunctionIterator functions = functionManager.getFunctions(true);

    while (functions.hasNext() && !monitor.isCancelled()) {
      Function function = functions.next();

      if (looksLikeDecryptionRoutine(function)) {
        DecryptionRoutine routine = analyzeDecryptionRoutine(function);
        if (routine != null) {
          decryptionRoutines.put(function.getEntryPoint(), routine);
          decryptionFunctionsFound++;

          String algoName = routine.algorithmType.toString();
          decryptionAlgorithms.put(algoName, decryptionAlgorithms.getOrDefault(algoName, 0) + 1);

          println("  Found decryption routine at " + function.getEntryPoint() + " (" + routine.algorithmType + ")");
        }
      }
    }
  }

  private boolean looksLikeDecryptionRoutine(Function function) {
    if (function == null) return false;

    String funcName = function.getName().toLowerCase();
    if (funcName.contains("decrypt") || funcName.contains("deobfuscate") || funcName.contains("decode")) {
      return true;
    }

    Listing listing = currentProgram.getListing();
    InstructionIterator instructions = listing.getInstructions(function.getBody(), true);

    int xorCount = 0;
    int rotateCount = 0;
    int shiftCount = 0;
    int loopCount = 0;
    int stringLoadCount = 0;

    while (instructions.hasNext() && !monitor.isCancelled()) {
      Instruction inst = instructions.next();
      String mnemonic = inst.getMnemonicString().toLowerCase();

      if (mnemonic.equals("xor")) {
        xorCount++;
      } else if (mnemonic.contains("rol") || mnemonic.contains("ror")) {
        rotateCount++;
      } else if (mnemonic.contains("shl") || mnemonic.contains("shr")) {
        shiftCount++;
      }

      if (inst.getFlowType().isJump()) {
        Address target = inst.getAddress(0);
        if (target != null && target.compareTo(inst.getAddress()) < 0) {
          loopCount++;
        }
      }

      PcodeOp[] pcodeOps = inst.getPcode();
      if (pcodeOps != null) {
        for (PcodeOp op : pcodeOps) {
          if (op.getOpcode() == PcodeOp.LOAD) {
            stringLoadCount++;
          }
        }
      }
    }

    int totalInstructions = function.getBody().getNumAddresses();
    if (totalInstructions > 0) {
      double xorDensity = (double) xorCount / totalInstructions;

      if (xorDensity > 0.15 && loopCount > 0 && stringLoadCount > 3) {
        return true;
      }

      if (xorCount > 10 && loopCount > 0) {
        return true;
      }

      if ((rotateCount + shiftCount) > 8 && loopCount > 0 && stringLoadCount > 2) {
        return true;
      }
    }

    return false;
  }

  private DecryptionRoutine analyzeDecryptionRoutine(Function function) {
    if (function == null) return null;

    DecryptionRoutine routine = new DecryptionRoutine();
    routine.address = function.getEntryPoint();
    routine.functionName = function.getName();

    Listing listing = currentProgram.getListing();
    InstructionIterator instructions = listing.getInstructions(function.getBody(), true);

    int xorOps = 0;
    int addOps = 0;
    int subOps = 0;
    int rotateOps = 0;
    byte[] keyCandidate = null;

    while (instructions.hasNext() && !monitor.isCancelled()) {
      Instruction inst = instructions.next();
      String mnemonic = inst.getMnemonicString().toLowerCase();

      if (mnemonic.equals("xor")) {
        xorOps++;

        Object[] operands = inst.getOpObjects(1);
        if (operands.length > 0 && operands[0] instanceof Scalar) {
          Scalar scalar = (Scalar) operands[0];
          long value = scalar.getValue();

          if (value > 0 && value < 256) {
            keyCandidate = new byte[] {(byte) value};
          }
        }
      } else if (mnemonic.equals("add")) {
        addOps++;
      } else if (mnemonic.equals("sub")) {
        subOps++;
      } else if (mnemonic.contains("rol") || mnemonic.contains("ror")) {
        rotateOps++;
      }
    }

    if (xorOps > addOps && xorOps > subOps && xorOps > rotateOps) {
      routine.algorithmType = DecryptionAlgorithm.XOR_CIPHER;
      routine.key = keyCandidate;
    } else if (rotateOps > 5) {
      routine.algorithmType = DecryptionAlgorithm.ROT_CIPHER;
    } else if (addOps > 10 || subOps > 10) {
      routine.algorithmType = DecryptionAlgorithm.ADD_CIPHER;
    } else {
      routine.algorithmType = DecryptionAlgorithm.CUSTOM;
    }

    routine.confidence = calculateRoutineConfidence(xorOps, addOps, subOps, rotateOps);

    return routine;
  }

  private double calculateRoutineConfidence(int xorOps, int addOps, int subOps, int rotateOps) {
    int totalOps = xorOps + addOps + subOps + rotateOps;

    if (totalOps == 0) return 0.0;

    double maxOps = Math.max(Math.max(xorOps, addOps), Math.max(subOps, rotateOps));
    double dominance = maxOps / totalOps;

    double baseConfidence = 0.5 + (dominance * 0.4);

    if (totalOps > 20) {
      baseConfidence += 0.1;
    }

    return Math.min(0.95, baseConfidence);
  }

  private void locateEncryptedStrings() {
    Memory memory = currentProgram.getMemory();
    MemoryBlock[] blocks = memory.getBlocks();

    for (MemoryBlock block : blocks) {
      if (monitor.isCancelled()) break;

      if (block.getName().toLowerCase().contains("data") || block.getName().toLowerCase().contains("rdata")) {
        scanBlockForEncryptedStrings(block);
      }
    }

    ReferenceManager refManager = currentProgram.getReferenceManager();
    for (DecryptionRoutine routine : decryptionRoutines.values()) {
      if (monitor.isCancelled()) break;

      Function function = currentProgram.getFunctionManager().getFunctionAt(routine.address);
      if (function != null) {
        ReferenceIterator refs = refManager.getReferencesTo(function.getEntryPoint());

        while (refs.hasNext()) {
          Reference ref = refs.next();
          Address callSite = ref.getFromAddress();

          Address stringAddr = findStringArgument(callSite);
          if (stringAddr != null) {
            byte[] data = readPotentialString(stringAddr);
            if (data != null && looksEncrypted(data)) {
              EncryptedString encStr = new EncryptedString();
              encStr.address = stringAddr;
              encStr.data = data;
              encStr.decryptionRoutine = routine.address;
              encStr.callSite = callSite;

              encryptedStrings.put(stringAddr, encStr);
            }
          }
        }
      }
    }
  }

  private void scanBlockForEncryptedStrings(MemoryBlock block) {
    Address current = block.getStart();
    Address end = block.getEnd();

    while (current.compareTo(end) < 0 && !monitor.isCancelled()) {
      byte[] data = readPotentialString(current);

      if (data != null && data.length >= 8 && looksEncrypted(data)) {
        EncryptedString encStr = new EncryptedString();
        encStr.address = current;
        encStr.data = data;

        encryptedStrings.put(current, encStr);
      }

      try {
        current = current.add(4);
      } catch (Exception e) {
        break;
      }
    }
  }

  private Address findStringArgument(Address callSite) {
    Instruction inst = currentProgram.getListing().getInstructionAt(callSite);
    if (inst == null) return null;

    for (int i = 0; i < 5; i++) {
      Instruction prev = inst.getPrevious();
      if (prev == null) break;

      String mnemonic = prev.getMnemonicString().toLowerCase();
      if (mnemonic.equals("lea") || mnemonic.equals("mov") || mnemonic.equals("push")) {
        Object[] operands = prev.getOpObjects(1);
        if (operands.length > 0 && operands[0] instanceof Address) {
          return (Address) operands[0];
        }
      }

      inst = prev;
    }

    return null;
  }

  private byte[] readPotentialString(Address addr) {
    if (addr == null) return null;

    try {
      Memory memory = currentProgram.getMemory();
      byte[] buffer = new byte[256];
      int bytesRead = memory.getBytes(addr, buffer);

      if (bytesRead == 0) return null;

      int length = 0;
      for (int i = 0; i < buffer.length; i++) {
        if (buffer[i] == 0) {
          length = i;
          break;
        }
      }

      if (length == 0) {
        length = Math.min(buffer.length, bytesRead);
      }

      byte[] result = new byte[length];
      System.arraycopy(buffer, 0, result, 0, length);
      return result;

    } catch (Exception e) {
      return null;
    }
  }

  private boolean looksEncrypted(byte[] data) {
    if (data == null || data.length < 4) return false;

    int printableChars = 0;
    int highEntropyBytes = 0;

    for (byte b : data) {
      int unsigned = b & 0xFF;

      if (unsigned >= 32 && unsigned < 127) {
        printableChars++;
      }

      if (unsigned > 127 || unsigned < 32) {
        highEntropyBytes++;
      }
    }

    double printableRatio = (double) printableChars / data.length;
    double highEntropyRatio = (double) highEntropyBytes / data.length;

    if (highEntropyRatio > 0.5 && printableRatio < 0.7) {
      return true;
    }

    double entropy = calculateEntropy(data);
    if (entropy > 6.0 && entropy < 7.9) {
      return true;
    }

    return false;
  }

  private double calculateEntropy(byte[] data) {
    if (data == null || data.length == 0) return 0.0;

    int[] frequency = new int[256];
    for (byte b : data) {
      frequency[b & 0xFF]++;
    }

    double entropy = 0.0;
    for (int count : frequency) {
      if (count > 0) {
        double probability = (double) count / data.length;
        entropy -= probability * (Math.log(probability) / Math.log(2));
      }
    }

    return entropy;
  }

  private void attemptAutomatedDecryption() {
    for (Map.Entry<Address, EncryptedString> entry : encryptedStrings.entrySet()) {
      if (monitor.isCancelled()) break;

      Address addr = entry.getKey();
      EncryptedString encStr = entry.getValue();

      DecryptionRoutine routine = null;
      if (encStr.decryptionRoutine != null) {
        routine = decryptionRoutines.get(encStr.decryptionRoutine);
      }

      if (routine == null) {
        routine = guessDecryptionRoutine(encStr);
      }

      if (routine != null) {
        String decrypted = decryptString(encStr, routine);

        if (decrypted != null && looksLikeValidString(decrypted)) {
          encStr.decryptedValue = decrypted;
          stringsDecrypted++;

          println("  Decrypted at " + addr + ": \"" + sanitizeForDisplay(decrypted) + "\"");

          try {
            setEOLComment(addr, "Decrypted: " + sanitizeForDisplay(decrypted));
          } catch (Exception e) {
          }
        }
      }
    }
  }

  private DecryptionRoutine guessDecryptionRoutine(EncryptedString encStr) {
    for (DecryptionRoutine routine : decryptionRoutines.values()) {
      if (routine.confidence > 0.7) {
        return routine;
      }
    }

    DecryptionRoutine genericRoutine = new DecryptionRoutine();
    genericRoutine.algorithmType = DecryptionAlgorithm.XOR_CIPHER;
    genericRoutine.key = new byte[] {(byte) 0xFF};
    genericRoutine.confidence = 0.5;

    return genericRoutine;
  }

  private String decryptString(EncryptedString encStr, DecryptionRoutine routine) {
    if (encStr == null || encStr.data == null || routine == null) {
      return null;
    }

    byte[] decrypted = null;

    switch (routine.algorithmType) {
      case XOR_CIPHER:
        decrypted = decryptXOR(encStr.data, routine.key);
        break;

      case ROT_CIPHER:
        decrypted = decryptROT(encStr.data, 13);
        break;

      case ADD_CIPHER:
        decrypted = decryptADD(encStr.data, routine.key);
        break;

      case CUSTOM:
        decrypted = attemptBruteForce(encStr.data);
        break;
    }

    if (decrypted != null) {
      try {
        return new String(decrypted, StandardCharsets.UTF_8);
      } catch (Exception e) {
        return new String(decrypted, StandardCharsets.ISO_8859_1);
      }
    }

    return null;
  }

  private byte[] decryptXOR(byte[] data, byte[] key) {
    if (data == null) return null;

    if (key == null || key.length == 0) {
      key = new byte[] {(byte) 0xFF};
    }

    byte[] result = new byte[data.length];

    for (int i = 0; i < data.length; i++) {
      result[i] = (byte) (data[i] ^ key[i % key.length]);
    }

    return result;
  }

  private byte[] decryptROT(byte[] data, int shift) {
    if (data == null) return null;

    byte[] result = new byte[data.length];

    for (int i = 0; i < data.length; i++) {
      int b = data[i] & 0xFF;

      if (b >= 'A' && b <= 'Z') {
        result[i] = (byte) (((b - 'A' + shift) % 26) + 'A');
      } else if (b >= 'a' && b <= 'z') {
        result[i] = (byte) (((b - 'a' + shift) % 26) + 'a');
      } else {
        result[i] = data[i];
      }
    }

    return result;
  }

  private byte[] decryptADD(byte[] data, byte[] key) {
    if (data == null) return null;

    if (key == null || key.length == 0) {
      key = new byte[] {1};
    }

    byte[] result = new byte[data.length];

    for (int i = 0; i < data.length; i++) {
      result[i] = (byte) (data[i] - key[i % key.length]);
    }

    return result;
  }

  private byte[] attemptBruteForce(byte[] data) {
    if (data == null || data.length == 0) return null;

    for (int key = 1; key < 256; key++) {
      byte[] candidate = decryptXOR(data, new byte[] {(byte) key});

      if (looksLikeValidString(new String(candidate, StandardCharsets.ISO_8859_1))) {
        return candidate;
      }
    }

    return null;
  }

  private boolean looksLikeValidString(String str) {
    if (str == null || str.length() < 3) return false;

    int printableCount = 0;
    int alphaCount = 0;

    for (char c : str.toCharArray()) {
      if (c >= 32 && c < 127) {
        printableCount++;

        if (Character.isLetter(c)) {
          alphaCount++;
        }
      }
    }

    double printableRatio = (double) printableCount / str.length();
    double alphaRatio = (double) alphaCount / str.length();

    if (printableRatio > 0.8 && alphaRatio > 0.3) {
      return true;
    }

    String[] commonWords = {"the", "and", "for", "with", "from", "this", "that", "http", "www", "error", "warning", "file", "data"};
    String lowerStr = str.toLowerCase();

    for (String word : commonWords) {
      if (lowerStr.contains(word)) {
        return true;
      }
    }

    return false;
  }

  private String sanitizeForDisplay(String str) {
    if (str == null) return "";

    String sanitized = str.replaceAll("[\\p{Cntrl}&&[^\n\r\t]]", "");

    if (sanitized.length() > 80) {
      sanitized = sanitized.substring(0, 77) + "...";
    }

    return sanitized;
  }

  private void generateDecryptionReport() {
    try {
      File outputDir = new File(currentProgram.getExecutablePath()).getParentFile();
      if (outputDir == null) {
        outputDir = new File(".");
      }

      File reportFile = new File(outputDir, currentProgram.getName() + "_decrypted_strings.txt");

      try (PrintWriter writer = new PrintWriter(new FileWriter(reportFile))) {
        writer.println("=== DECRYPTED STRINGS REPORT ===");
        writer.println("Program: " + currentProgram.getName());
        writer.println("Timestamp: " + new Date());
        writer.println("Total encrypted strings: " + encryptedStrings.size());
        writer.println("Successfully decrypted: " + stringsDecrypted);
        writer.println();

        writer.println("=== DECRYPTED STRINGS ===");
        for (Map.Entry<Address, EncryptedString> entry : encryptedStrings.entrySet()) {
          EncryptedString encStr = entry.getValue();

          if (encStr.decryptedValue != null) {
            writer.println();
            writer.println("Address: " + encStr.address);
            if (encStr.callSite != null) {
              writer.println("Called from: " + encStr.callSite);
            }
            if (encStr.decryptionRoutine != null) {
              writer.println("Decryption routine: " + encStr.decryptionRoutine);
            }
            writer.println("Decrypted value: " + encStr.decryptedValue);
          }
        }
      }

      println("\nReport saved to: " + reportFile.getAbsolutePath());

    } catch (Exception e) {
      println("Failed to generate report: " + e.getMessage());
    }
  }

  private enum DecryptionAlgorithm {
    XOR_CIPHER,
    ROT_CIPHER,
    ADD_CIPHER,
    CUSTOM
  }

  private class DecryptionRoutine {
    Address address;
    String functionName;
    DecryptionAlgorithm algorithmType;
    byte[] key;
    double confidence;
  }

  private class EncryptedString {
    Address address;
    byte[] data;
    Address decryptionRoutine;
    Address callSite;
    String decryptedValue;
  }
}
