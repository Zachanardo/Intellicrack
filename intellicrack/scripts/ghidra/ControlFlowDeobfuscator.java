import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class ControlFlowDeobfuscator extends GhidraScript {

  private final Map<Address, ControlFlowPattern> obfuscationPatterns = new HashMap<>();
  private final Map<Address, Address> jumpTableResolutions = new HashMap<>();
  private final Set<Address> deadCodeBlocks = new HashSet<>();
  private final Set<Address> opaquePredicates = new HashSet<>();
  private int patchesApplied = 0;

  @Override
  public void run() throws Exception {
    println("=== Control Flow Deobfuscator ===");
    println("Analyzing: " + currentProgram.getName());
    println();

    FunctionManager functionManager = currentProgram.getFunctionManager();
    FunctionIterator functions = functionManager.getFunctions(true);

    int totalFunctions = functionManager.getFunctionCount();
    int processedFunctions = 0;
    int obfuscatedFunctions = 0;

    while (functions.hasNext() && !monitor.isCancelled()) {
      Function function = functions.next();
      processedFunctions++;

      if (processedFunctions % 100 == 0) {
        println("Progress: " + processedFunctions + "/" + totalFunctions + " functions");
      }

      if (analyzeFunctionControlFlow(function)) {
        obfuscatedFunctions++;
      }
    }

    println("\n=== Analysis Summary ===");
    println("Total functions analyzed: " + processedFunctions);
    println("Obfuscated functions found: " + obfuscatedFunctions);
    println("Opaque predicates detected: " + opaquePredicates.size());
    println("Dead code blocks found: " + deadCodeBlocks.size());
    println("Jump table resolutions: " + jumpTableResolutions.size());
    println();

    if (askYesNo("Deobfuscation Analysis", "Apply deobfuscation patches?")) {
      applyDeobfuscationPatches();
      println("\nPatches applied: " + patchesApplied);
    }
  }

  private boolean analyzeFunctionControlFlow(Function function) {
    if (function == null) {
      return false;
    }

    boolean hasObfuscation = false;

    hasObfuscation |= detectOpaquePredicates(function);
    hasObfuscation |= detectDeadCodeBlocks(function);
    hasObfuscation |= detectJunkInstructions(function);
    hasObfuscation |= detectIndirectJumps(function);
    hasObfuscation |= detectControlFlowFlattening(function);

    if (hasObfuscation) {
      performAdvancedDecompilerAnalysis(function);
    }

    return hasObfuscation;
  }

  private boolean detectOpaquePredicates(Function function) {
    Listing listing = currentProgram.getListing();
    InstructionIterator instructions = listing.getInstructions(function.getBody(), true);

    boolean foundOpaquePredicates = false;

    while (instructions.hasNext() && !monitor.isCancelled()) {
      Instruction inst = instructions.next();

      if (inst.getFlowType().isConditional()) {
        if (isOpaquePredicate(inst)) {
          opaquePredicates.add(inst.getAddress());
          foundOpaquePredicates = true;

          ControlFlowPattern pattern = new ControlFlowPattern();
          pattern.type = ObfuscationType.OPAQUE_PREDICATE;
          pattern.address = inst.getAddress();
          pattern.confidence = 0.85;
          pattern.description = "Opaque predicate detected at " + inst.getAddress();

          obfuscationPatterns.put(inst.getAddress(), pattern);
        }
      }
    }

    return foundOpaquePredicates;
  }

  private boolean isOpaquePredicate(Instruction inst) {
    if (inst == null || !inst.getFlowType().isConditional()) {
      return false;
    }

    PcodeOp[] pcodeOps = inst.getPcode();
    if (pcodeOps == null || pcodeOps.length == 0) {
      return false;
    }

    for (PcodeOp op : pcodeOps) {
      int opcode = op.getOpcode();

      if (opcode == PcodeOp.CBRANCH) {
        Varnode condition = op.getInput(1);
        if (condition != null) {
          if (isAlwaysTrueCondition(condition, pcodeOps)) {
            return true;
          }
          if (isAlwaysFalseCondition(condition, pcodeOps)) {
            return true;
          }
          if (isInvariantCondition(condition, pcodeOps)) {
            return true;
          }
        }
      }
    }

    Address target1 = inst.getAddress(0);
    Address fallthrough = inst.getFallThrough();

    if (target1 != null && fallthrough != null) {
      return analyzeBranchPaths(target1, fallthrough);
    }

    return false;
  }

  private boolean isAlwaysTrueCondition(Varnode condition, PcodeOp[] pcodeOps) {
    if (condition == null) {
      return false;
    }

    if (condition.isConstant() && condition.getOffset() != 0) {
      return true;
    }

    for (PcodeOp op : pcodeOps) {
      if (op.getOutput() != null && op.getOutput().equals(condition)) {
        int opcode = op.getOpcode();

        if (opcode == PcodeOp.INT_EQUAL) {
          Varnode input1 = op.getInput(0);
          Varnode input2 = op.getInput(1);

          if (input1 != null && input2 != null && input1.equals(input2)) {
            return true;
          }
        }

        if (opcode == PcodeOp.BOOL_OR) {
          Varnode input1 = op.getInput(0);
          Varnode input2 = op.getInput(1);

          if (input1 != null && input1.isConstant() && input1.getOffset() != 0) {
            return true;
          }
          if (input2 != null && input2.isConstant() && input2.getOffset() != 0) {
            return true;
          }
        }
      }
    }

    return false;
  }

  private boolean isAlwaysFalseCondition(Varnode condition, PcodeOp[] pcodeOps) {
    if (condition == null) {
      return false;
    }

    if (condition.isConstant() && condition.getOffset() == 0) {
      return true;
    }

    for (PcodeOp op : pcodeOps) {
      if (op.getOutput() != null && op.getOutput().equals(condition)) {
        int opcode = op.getOpcode();

        if (opcode == PcodeOp.INT_NOTEQUAL) {
          Varnode input1 = op.getInput(0);
          Varnode input2 = op.getInput(1);

          if (input1 != null && input2 != null && input1.equals(input2)) {
            return true;
          }
        }

        if (opcode == PcodeOp.BOOL_AND) {
          Varnode input1 = op.getInput(0);
          Varnode input2 = op.getInput(1);

          if (input1 != null && input1.isConstant() && input1.getOffset() == 0) {
            return true;
          }
          if (input2 != null && input2.isConstant() && input2.getOffset() == 0) {
            return true;
          }
        }
      }
    }

    return false;
  }

  private boolean isInvariantCondition(Varnode condition, PcodeOp[] pcodeOps) {
    if (condition == null) {
      return false;
    }

    Set<Varnode> dependentVarnodes = new HashSet<>();
    dependentVarnodes.add(condition);

    boolean changed = true;
    while (changed) {
      changed = false;
      Set<Varnode> newDependents = new HashSet<>();

      for (PcodeOp op : pcodeOps) {
        Varnode output = op.getOutput();
        if (output != null && dependentVarnodes.contains(output)) {
          for (int i = 0; i < op.getNumInputs(); i++) {
            Varnode input = op.getInput(i);
            if (input != null && !input.isConstant() && dependentVarnodes.add(input)) {
              newDependents.add(input);
              changed = true;
            }
          }
        }
      }
    }

    int constantCount = 0;
    for (Varnode v : dependentVarnodes) {
      if (v.isConstant()) {
        constantCount++;
      }
    }

    return constantCount == dependentVarnodes.size() - 1;
  }

  private boolean analyzeBranchPaths(Address trueBranch, Address falseBranch) {
    if (trueBranch == null || falseBranch == null) {
      return false;
    }

    Instruction trueInst = currentProgram.getListing().getInstructionAt(trueBranch);
    Instruction falseInst = currentProgram.getListing().getInstructionAt(falseBranch);

    if (trueInst != null && falseInst != null) {
      if (trueInst.getFlowType().isJump() && falseInst.getFlowType().isJump()) {
        Address trueTarget = trueInst.getAddress(0);
        Address falseTarget = falseInst.getAddress(0);

        return trueTarget != null && falseTarget != null && trueTarget.equals(falseTarget);
      }
    }

    return false;
  }

  private boolean detectDeadCodeBlocks(Function function) {
    BasicBlockModel blockModel = new BasicBlockModel(currentProgram);
    boolean foundDeadCode = false;

    try {
      CodeBlockIterator blocks = blockModel.getCodeBlocksForFunction(function, monitor);
      Set<Address> reachableBlocks = new HashSet<>();

      reachableBlocks.add(function.getEntryPoint());

      boolean changed = true;
      while (changed && !monitor.isCancelled()) {
        changed = false;
        blocks = blockModel.getCodeBlocksForFunction(function, monitor);

        while (blocks.hasNext()) {
          CodeBlock block = blocks.next();
          Address blockStart = block.getFirstStartAddress();

          if (reachableBlocks.contains(blockStart)) {
            CodeBlockReferenceIterator refs = block.getDestinations(monitor);

            while (refs.hasNext()) {
              CodeBlockReference ref = refs.next();
              Address destAddr = ref.getDestinationAddress();

              if (reachableBlocks.add(destAddr)) {
                changed = true;
              }
            }
          }
        }
      }

      blocks = blockModel.getCodeBlocksForFunction(function, monitor);
      while (blocks.hasNext()) {
        CodeBlock block = blocks.next();
        Address blockStart = block.getFirstStartAddress();

        if (!reachableBlocks.contains(blockStart)) {
          deadCodeBlocks.add(blockStart);
          foundDeadCode = true;

          ControlFlowPattern pattern = new ControlFlowPattern();
          pattern.type = ObfuscationType.DEAD_CODE;
          pattern.address = blockStart;
          pattern.confidence = 0.90;
          pattern.description = "Unreachable code block at " + blockStart;

          obfuscationPatterns.put(blockStart, pattern);
        }
      }

    } catch (Exception e) {
      throw new RuntimeException(e);
    }

    return foundDeadCode;
  }

  private boolean detectJunkInstructions(Function function) {
    Listing listing = currentProgram.getListing();
    InstructionIterator instructions = listing.getInstructions(function.getBody(), true);

    boolean foundJunk = false;
    int junkCount = 0;

    while (instructions.hasNext() && !monitor.isCancelled()) {
      Instruction inst = instructions.next();

      if (isJunkInstruction(inst)) {
        junkCount++;

        if (junkCount > 5) {
          foundJunk = true;

          ControlFlowPattern pattern = new ControlFlowPattern();
          pattern.type = ObfuscationType.JUNK_INSTRUCTIONS;
          pattern.address = inst.getAddress();
          pattern.confidence = 0.75;
          pattern.description = "Junk instructions pattern in " + function.getName();

          obfuscationPatterns.put(inst.getAddress(), pattern);
        }
      }
    }

    return foundJunk;
  }

  private boolean isJunkInstruction(Instruction inst) {
    if (inst == null) {
      return false;
    }

    String mnemonic = inst.getMnemonicString().toLowerCase();

    if ("nop".equals(mnemonic)) {
      return true;
    }

    if ("push".equals(mnemonic) || "pop".equals(mnemonic)) {
      Instruction next = inst.getNext();
      if (next != null) {
        String nextMnemonic = next.getMnemonicString().toLowerCase();
        if (("push".equals(mnemonic) && "pop".equals(nextMnemonic))
            || ("pop".equals(mnemonic) && "push".equals(nextMnemonic))) {

          Object[] ops1 = inst.getOpObjects(0);
          Object[] ops2 = next.getOpObjects(0);

          if (ops1.length > 0 && ops2.length > 0 && ops1[0].equals(ops2[0])) {
            return true;
          }
        }
      }
    }

    if ("mov".equals(mnemonic) || "xchg".equals(mnemonic)) {
      Object[] operands = inst.getOpObjects(0);
      if (operands.length >= 2 && operands[0].equals(operands[1])) {
        return true;
      }
    }

    PcodeOp[] pcodeOps = inst.getPcode();
    if (pcodeOps != null) {
      for (PcodeOp op : pcodeOps) {
        Varnode output = op.getOutput();
        if (output != null && output.isRegister()) {
          boolean outputUsed = false;

          Instruction nextInst = inst.getNext();
          if (nextInst != null) {
            PcodeOp[] nextPcode = nextInst.getPcode();
            if (nextPcode != null) {
              for (PcodeOp nextOp : nextPcode) {
                for (int i = 0; i < nextOp.getNumInputs(); i++) {
                  Varnode input = nextOp.getInput(i);
                  if (input != null && input.equals(output)) {
                    outputUsed = true;
                    break;
                  }
                }
              }
            }
          }

          if (!outputUsed && !isVolatileRegister(output)) {
            return true;
          }
        }
      }
    }

    return false;
  }

  private boolean isVolatileRegister(Varnode varnode) {
    if (varnode == null || !varnode.isRegister()) {
      return false;
    }

    String registerName = currentProgram.getRegister(varnode).getName().toLowerCase();

    String[] volatileRegs = {"rsp", "esp", "sp", "rbp", "ebp", "bp", "rip", "eip", "ip"};

    for (String volReg : volatileRegs) {
      if (registerName.contains(volReg)) {
        return true;
      }
    }

    return false;
  }

  private boolean detectIndirectJumps(Function function) {
    Listing listing = currentProgram.getListing();
    InstructionIterator instructions = listing.getInstructions(function.getBody(), true);

    boolean foundIndirectJumps = false;

    while (instructions.hasNext() && !monitor.isCancelled()) {
      Instruction inst = instructions.next();

      if (inst.getFlowType().isJump() && inst.getFlowType().isComputed()) {
        Address jumpTarget = resolveIndirectJump(inst);

        if (jumpTarget != null) {
          jumpTableResolutions.put(inst.getAddress(), jumpTarget);
          foundIndirectJumps = true;

          ControlFlowPattern pattern = new ControlFlowPattern();
          pattern.type = ObfuscationType.INDIRECT_JUMP;
          pattern.address = inst.getAddress();
          pattern.confidence = 0.80;
          pattern.description = "Indirect jump resolved to " + jumpTarget;

          obfuscationPatterns.put(inst.getAddress(), pattern);
        }
      }
    }

    return foundIndirectJumps;
  }

  private Address resolveIndirectJump(Instruction inst) {
    if (inst == null) {
      return null;
    }

    PcodeOp[] pcodeOps = inst.getPcode();
    if (pcodeOps == null) {
      return null;
    }

    for (PcodeOp op : pcodeOps) {
      if (op.getOpcode() == PcodeOp.BRANCHIND || op.getOpcode() == PcodeOp.CALLIND) {
        Varnode target = op.getInput(0);
        if (target != null && target.isConstant()) {
          try {
            return currentProgram
                .getAddressFactory()
                .getDefaultAddressSpace()
                .getAddress(target.getOffset());
          } catch (Exception e) {
            throw new RuntimeException(e);
          }
        }
      }
    }

    Instruction prevInst = inst.getPrevious();
    if (prevInst != null) {
      String mnemonic = prevInst.getMnemonicString().toLowerCase();
      if ("mov".equals(mnemonic) || "lea".equals(mnemonic)) {
        Object[] operands = prevInst.getOpObjects(1);
        if (operands.length > 0 && operands[0] instanceof Address) {
          return (Address) operands[0];
        }
      }
    }

    return null;
  }

  private boolean detectControlFlowFlattening(Function function) {
    BasicBlockModel blockModel = new BasicBlockModel(currentProgram);
    boolean foundFlattening = false;

    try {
      CodeBlockIterator blocks = blockModel.getCodeBlocksForFunction(function, monitor);

      Address dispatcherBlock = null;
      int blocksWithSwitchPattern = 0;

      while (blocks.hasNext() && !monitor.isCancelled()) {
        CodeBlock block = blocks.next();

        if (looksLikeDispatcherBlock(block)) {
          dispatcherBlock = block.getFirstStartAddress();
          blocksWithSwitchPattern++;
        }
      }

      if (dispatcherBlock != null && blocksWithSwitchPattern >= 1) {
        foundFlattening = true;

        ControlFlowPattern pattern = new ControlFlowPattern();
        pattern.type = ObfuscationType.CONTROL_FLOW_FLATTENING;
        pattern.address = dispatcherBlock;
        pattern.confidence = 0.88;
        pattern.description = "Control flow flattening dispatcher at " + dispatcherBlock;

        obfuscationPatterns.put(dispatcherBlock, pattern);
      }

    } catch (Exception e) {
      throw new RuntimeException(e);
    }

    return foundFlattening;
  }

  private boolean looksLikeDispatcherBlock(CodeBlock block) {
    if (block == null) {
      return false;
    }

    int switchLikeInstructions = 0;
    int indirectJumps = 0;

    Listing listing = currentProgram.getListing();
    InstructionIterator instructions = listing.getInstructions(block, true);

    while (instructions.hasNext()) {
      Instruction inst = instructions.next();

      if (inst.getFlowType().isComputed()) {
        indirectJumps++;
      }

      String mnemonic = inst.getMnemonicString().toLowerCase();
      if (mnemonic.contains("cmp") || mnemonic.contains("test")) {
        switchLikeInstructions++;
      }
    }

    return indirectJumps >= 1 && switchLikeInstructions >= 2;
  }

  private void applyDeobfuscationPatches() {
    println("\n=== Applying Deobfuscation Patches ===");

    for (Map.Entry<Address, ControlFlowPattern> entry : obfuscationPatterns.entrySet()) {
      Address addr = entry.getKey();
      ControlFlowPattern pattern = entry.getValue();

      if (pattern.confidence > 0.75) {
        switch (pattern.type) {
          case OPAQUE_PREDICATE:
            patchOpaquePredicate(addr, pattern);
            break;
          case DEAD_CODE:
            patchDeadCode(addr, pattern);
            break;
          case JUNK_INSTRUCTIONS:
            patchJunkInstructions(addr, pattern);
            break;
          case INDIRECT_JUMP:
            patchIndirectJump(addr, pattern);
            break;
          case CONTROL_FLOW_FLATTENING:
            addDispatcherComment(addr, pattern);
            break;
        }
      }
    }
  }

  private void patchOpaquePredicate(Address addr, ControlFlowPattern pattern) {
    try {
      Instruction inst = currentProgram.getListing().getInstructionAt(addr);
      if (inst != null) {
        setEOLComment(
            addr,
            "OPAQUE PREDICATE - Always takes same branch (confidence: "
                + String.format("%.2f", pattern.confidence)
                + ")");
        patchesApplied++;
      }
    } catch (Exception e) {
      println("Failed to patch opaque predicate at " + addr + ": " + e.getMessage());
    }
  }

  private void patchDeadCode(Address addr, ControlFlowPattern pattern) {
    try {
      setPreComment(
          addr,
          "DEAD CODE - Unreachable block (confidence: "
              + String.format("%.2f", pattern.confidence)
              + ")");
      patchesApplied++;
    } catch (Exception e) {
      println("Failed to mark dead code at " + addr + ": " + e.getMessage());
    }
  }

  private void patchJunkInstructions(Address addr, ControlFlowPattern pattern) {
    try {
      String comment = "JUNK INSTRUCTION - No functional effect (confidence: "
          + String.format("%.2f", pattern.confidence) + ")";
      setEOLComment(addr, comment);
      patchesApplied++;
    } catch (Exception e) {
      println("Failed to mark junk instruction at " + addr + ": " + e.getMessage());
    }
  }

  private void patchIndirectJump(Address addr, ControlFlowPattern pattern) {
    try {
      Address target = jumpTableResolutions.get(addr);
      if (target != null) {
        String comment = "Indirect jump resolves to: " + target
            + " (type: " + pattern.type + ", confidence: "
            + String.format("%.2f", pattern.confidence) + ")";
        setEOLComment(addr, comment);
        patchesApplied++;
      }
    } catch (Exception e) {
      println("Failed to patch indirect jump at " + addr + ": " + e.getMessage());
    }
  }

  private void addDispatcherComment(Address addr, ControlFlowPattern pattern) {
    try {
      String comment = "CONTROL FLOW FLATTENING DISPATCHER\n"
          + "This block acts as a state machine dispatcher for obfuscated control flow\n"
          + "Description: " + pattern.description;
      setPreComment(addr, comment);
      patchesApplied++;
    } catch (Exception e) {
      println("Failed to add dispatcher comment at " + addr + ": " + e.getMessage());
    }
  }

  private void performAdvancedDecompilerAnalysis(Function function) {
    DecompInterface decompInterface = new DecompInterface();
    DecompileOptions options = new DecompileOptions();
    decompInterface.setOptions(options);
    decompInterface.openProgram(currentProgram);

    try {
      DecompileResults results = decompInterface.decompileFunction(function, 60, monitor);
      if (results != null && results.decompileCompleted()) {
        HighFunction highFunc = results.getHighFunction();
        if (highFunc != null) {
          Iterator<PcodeOpAST> pcodeIter = highFunc.getPcodeOps();
          List<PcodeOpAST> cryptoOps = new ArrayList<>();
          while (pcodeIter.hasNext()) {
            PcodeOpAST pcodeOp = pcodeIter.next();
            if (pcodeOp.getOpcode() == PcodeOp.INT_XOR) {
              cryptoOps.add(pcodeOp);
            }
          }
          println("    Advanced pcode analysis found " + cryptoOps.size() + " XOR operations");
        }
      }
    } finally {
      decompInterface.dispose();
    }

    AddressSet functionAddresses = new AddressSet(function.getBody());
    println("    Function covers " + functionAddresses.getNumAddresses() + " addresses");

    Register[] contextRegs = currentProgram.getLanguage().getRegisters().toArray(new Register[0]);
    println("    Analyzing with " + contextRegs.length + " registers available");

    Symbol funcSymbol = getSymbolAt(function.getEntryPoint());
    if (funcSymbol != null) {
      Reference[] refs = getReferencesTo(function.getEntryPoint());
      println("    Symbol '" + funcSymbol.getName() + "' has " + refs.length + " references");
    }
  }

  private enum ObfuscationType {
    OPAQUE_PREDICATE,
    DEAD_CODE,
    JUNK_INSTRUCTIONS,
    INDIRECT_JUMP,
    CONTROL_FLOW_FLATTENING
  }

  private static final class ControlFlowPattern {
    ObfuscationType type;
    Address address;
    double confidence;
    String description;
  }
}
