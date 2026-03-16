import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class HackTranslatorApp {
    public static void main(String[] arguments) {
        if (arguments.length < 1 || arguments.length > 2) {
            System.out.println("Usage: java HackTranslatorApp input.asm [output.hack]");
            return;
        }

        Path sourceFile = Path.of(arguments[0]);
        Path targetFile = arguments.length == 2 ? Path.of(arguments[1]) : createHackPath(sourceFile);

        try {
            BinaryAssembler translator = new BinaryAssembler();
            translator.translate(sourceFile, targetFile);
            System.out.println("Created: " + targetFile);
        } catch (Exception problem) {
            System.out.println("Assembler error: " + problem.getMessage());
        }
    }

    private static Path createHackPath(Path asmFile) {
        String fileLabel = asmFile.getFileName().toString();
        int extensionIndex = fileLabel.lastIndexOf('.');
        String stem = extensionIndex == -1 ? fileLabel : fileLabel.substring(0, extensionIndex);
        Path folder = asmFile.getParent();
        return folder == null ? Path.of(stem + ".hack") : folder.resolve(stem + ".hack");
    }
}

class BinaryAssembler {
    private final AddressBook labelBook = new AddressBook();
    private final InstructionEncoder encoder = new InstructionEncoder();
    private int freeRamSlot = 16;

    public void translate(Path asmPath, Path hackPath) throws IOException {
        List<String> rawLines = Files.readAllLines(asmPath);
        SourceSanitizer cleaner = new SourceSanitizer(rawLines);

        registerLabels(cleaner.getInstructions());
        List<String> machineLines = generateBinary(cleaner.getInstructions());

        Files.write(hackPath, machineLines);
    }

    private void registerLabels(List<String> instructionList) {
        int romCounter = 0;

        for (String instruction : instructionList) {
            if (SourceSanitizer.identifyType(instruction) == InstructionKind.LABEL) {
                String marker = SourceSanitizer.extractSymbol(instruction);
                if (!labelBook.hasSymbol(marker)) {
                    labelBook.define(marker, romCounter);
                }
            } else {
                romCounter++;
            }
        }
    }

    private List<String> generateBinary(List<String> instructionList) {
        List<String> binaryLines = new ArrayList<>();

        for (String instruction : instructionList) {
            InstructionKind kind = SourceSanitizer.identifyType(instruction);

            if (kind == InstructionKind.LABEL) {
                continue;
            }

            if (kind == InstructionKind.ADDRESS) {
                String token = SourceSanitizer.extractSymbol(instruction);
                int memoryValue;

                if (token.matches("\\d+")) {
                    memoryValue = Integer.parseInt(token);
                } else {
                    if (!labelBook.hasSymbol(token)) {
                        labelBook.define(token, freeRamSlot++);
                    }
                    memoryValue = labelBook.lookup(token);
                }

                binaryLines.add(format16Bit(memoryValue));
            } else {
                String left = SourceSanitizer.extractDest(instruction);
                String middle = SourceSanitizer.extractComp(instruction);
                String right = SourceSanitizer.extractJump(instruction);

                String encoded = "111"
                        + encoder.encodeComp(middle)
                        + encoder.encodeDest(left)
                        + encoder.encodeJump(right);

                binaryLines.add(encoded);
            }
        }

        return binaryLines;
    }

    private String format16Bit(int number) {
        String binaryText = Integer.toBinaryString(number);
        if (binaryText.length() > 16) {
            binaryText = binaryText.substring(binaryText.length() - 16);
        }
        return String.format("%16s", binaryText).replace(' ', '0');
    }
}

class SourceSanitizer {
    private final List<String> instructions;

    public SourceSanitizer(List<String> inputLines) {
        this.instructions = normalize(inputLines);
    }

    public List<String> getInstructions() {
        return instructions;
    }

    private List<String> normalize(List<String> inputLines) {
        List<String> cleanedLines = new ArrayList<>();

        for (String original : inputLines) {
            String stripped = stripInlineComment(original).trim();
            stripped = stripped.replaceAll("\\s+", "");
            if (!stripped.isEmpty()) {
                cleanedLines.add(stripped);
            }
        }

        return cleanedLines;
    }

    private String stripInlineComment(String text) {
        int commentStart = text.indexOf("//");
        if (commentStart >= 0) {
            return text.substring(0, commentStart);
        }
        return text;
    }

    public static InstructionKind identifyType(String instruction) {
        if (instruction.startsWith("@")) {
            return InstructionKind.ADDRESS;
        }
        if (instruction.startsWith("(") && instruction.endsWith(")")) {
            return InstructionKind.LABEL;
        }
        return InstructionKind.COMPUTE;
    }

    public static String extractSymbol(String instruction) {
        if (instruction.startsWith("@")) {
            return instruction.substring(1);
        }
        return instruction.substring(1, instruction.length() - 1);
    }

    public static String extractDest(String instruction) {
        int equalPos = instruction.indexOf('=');
        return equalPos == -1 ? "" : instruction.substring(0, equalPos);
    }

    public static String extractComp(String instruction) {
        int equalPos = instruction.indexOf('=');
        int semicolonPos = instruction.indexOf(';');

        int begin = equalPos == -1 ? 0 : equalPos + 1;
        int finish = semicolonPos == -1 ? instruction.length() : semicolonPos;

        return instruction.substring(begin, finish);
    }

    public static String extractJump(String instruction) {
        int semicolonPos = instruction.indexOf(';');
        return semicolonPos == -1 ? "" : instruction.substring(semicolonPos + 1);
    }
}

class InstructionEncoder {
    private final Map<String, String> destinationBits = new HashMap<>();
    private final Map<String, String> computationBits = new HashMap<>();
    private final Map<String, String> jumpBits = new HashMap<>();

    public InstructionEncoder() {
        fillDestinationMap();
        fillComputationMap();
        fillJumpMap();
    }

    public String encodeDest(String key) {
        String bits = destinationBits.get(key);
        if (bits == null) {
            throw new IllegalArgumentException("Invalid dest mnemonic: " + key);
        }
        return bits;
    }

    public String encodeComp(String key) {
        String bits = computationBits.get(key);
        if (bits == null) {
            throw new IllegalArgumentException("Invalid comp mnemonic: " + key);
        }
        return bits;
    }

    public String encodeJump(String key) {
        String bits = jumpBits.get(key);
        if (bits == null) {
            throw new IllegalArgumentException("Invalid jump mnemonic: " + key);
        }
        return bits;
    }

    private void fillDestinationMap() {
        destinationBits.put("", "000");
        destinationBits.put("M", "001");
        destinationBits.put("D", "010");
        destinationBits.put("MD", "011");
        destinationBits.put("DM", "011");
        destinationBits.put("A", "100");
        destinationBits.put("AM", "101");
        destinationBits.put("MA", "101");
        destinationBits.put("AD", "110");
        destinationBits.put("DA", "110");
        destinationBits.put("AMD", "111");
        destinationBits.put("ADM", "111");
        destinationBits.put("MAD", "111");
        destinationBits.put("MDA", "111");
        destinationBits.put("DAM", "111");
        destinationBits.put("DMA", "111");
    }

    private void fillJumpMap() {
        jumpBits.put("", "000");
        jumpBits.put("JGT", "001");
        jumpBits.put("JEQ", "010");
        jumpBits.put("JGE", "011");
        jumpBits.put("JLT", "100");
        jumpBits.put("JNE", "101");
        jumpBits.put("JLE", "110");
        jumpBits.put("JMP", "111");
    }

    private void fillComputationMap() {
        computationBits.put("0", "0101010");
        computationBits.put("1", "0111111");
        computationBits.put("-1", "0111010");
        computationBits.put("D", "0001100");
        computationBits.put("A", "0110000");
        computationBits.put("!D", "0001101");
        computationBits.put("!A", "0110001");
        computationBits.put("-D", "0001111");
        computationBits.put("-A", "0110011");
        computationBits.put("D+1", "0011111");
        computationBits.put("1+D", "0011111");
        computationBits.put("A+1", "0110111");
        computationBits.put("1+A", "0110111");
        computationBits.put("D-1", "0001110");
        computationBits.put("-1+D", "0001110");
        computationBits.put("A-1", "0110010");
        computationBits.put("-1+A", "0110010");
        computationBits.put("D+A", "0000010");
        computationBits.put("A+D", "0000010");
        computationBits.put("D-A", "0010011");
        computationBits.put("-A+D", "0010011");
        computationBits.put("A-D", "0000111");
        computationBits.put("-D+A", "0000111");
        computationBits.put("D&A", "0000000");
        computationBits.put("A&D", "0000000");
        computationBits.put("D|A", "0010101");
        computationBits.put("A|D", "0010101");

        computationBits.put("M", "1110000");
        computationBits.put("!M", "1110001");
        computationBits.put("-M", "1110011");
        computationBits.put("M+1", "1110111");
        computationBits.put("1+M", "1110111");
        computationBits.put("M-1", "1110010");
        computationBits.put("-1+M", "1110010");
        computationBits.put("D+M", "1000010");
        computationBits.put("M+D", "1000010");
        computationBits.put("D-M", "1010011");
        computationBits.put("-M+D", "1010011");
        computationBits.put("M-D", "1000111");
        computationBits.put("-D+M", "1000111");
        computationBits.put("D&M", "1000000");
        computationBits.put("M&D", "1000000");
        computationBits.put("D|M", "1010101");
        computationBits.put("M|D", "1010101");
    }
}

class AddressBook {
    private final Map<String, Integer> symbolMap = new HashMap<>();

    public AddressBook() {
        symbolMap.put("SP", 0);
        symbolMap.put("LCL", 1);
        symbolMap.put("ARG", 2);
        symbolMap.put("THIS", 3);
        symbolMap.put("THAT", 4);
        symbolMap.put("SCREEN", 16384);
        symbolMap.put("KBD", 24576);

        for (int registerIndex = 0; registerIndex < 16; registerIndex++) {
            symbolMap.put("R" + registerIndex, registerIndex);
        }
    }

    public void define(String name, int value) {
        symbolMap.put(name, value);
    }

    public boolean hasSymbol(String name) {
        return symbolMap.containsKey(name);
    }

    public int lookup(String name) {
        return symbolMap.get(name);
    }
}

enum InstructionKind {
    ADDRESS,
    COMPUTE,
    LABEL
}