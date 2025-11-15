import java.io.*;
import java.security.*;
import java.util.*;
import javax.crypto.*;

public class TestScannerJava {

    static class TruePositives {
        public String tp01KeygenTrivial(String username) {
            return username + "12345";
        }

        public String tp02KeygenHardcoded() {
            return "AAAA-BBBB-CCCC-DDDD";
        }

        public void tp03PatcherNoBackup(String binaryPath, int offset, byte[] data) throws IOException {
            RandomAccessFile raf = new RandomAccessFile(binaryPath, "rw");
            raf.seek(offset);
            raf.write(data);
            raf.close();
        }

        public void tp04PatcherHardcoded(String filePath) throws IOException {
            RandomAccessFile raf = new RandomAccessFile(filePath, "rw");
            raf.seek(0x1000);
            raf.write(new byte[]{(byte)0x90, (byte)0x90});
            raf.close();
        }

        public boolean tp05ValidatorAlwaysTrue(String key) {
            return true;
        }

        public Map<String, Boolean> tp06AnalyzerStringOnly(String binaryPath) throws IOException {
            String content = new String(Files.readAllBytes(Paths.get(binaryPath)));
            Map<String, Boolean> result = new HashMap<>();
            result.put("has_license", content.contains("license"));
            return result;
        }

        public void tp07EmptyImpl() {
        }

        public byte[] tp08Placeholder(byte[] data) {
            byte[] result = data;
            return result;
        }

        public String tp09KeygenMd5Only(String user) throws NoSuchAlgorithmException {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hash = md.digest(user.getBytes());
            return bytesToHex(hash).substring(0, 16);
        }

        public byte[] tp10PatcherBlind(byte[] binary, byte[] patch) {
            byte[] result = new byte[binary.length + patch.length];
            System.arraycopy(binary, 0, result, 0, binary.length);
            System.arraycopy(patch, 0, result, binary.length, patch.length);
            return result;
        }

        public Map<String, String> tp11AnalyzerExtensionOnly(String path) {
            Map<String, String> result = new HashMap<>();
            result.put("type", path.endsWith(".exe") ? "PE" : "ELF");
            return result;
        }

        public String tp12HookSkeleton(String funcName) {
            return String.format("Interceptor.attach(ptr('%s'), {});", funcName);
        }

        private String bytesToHex(byte[] bytes) {
            StringBuilder sb = new StringBuilder();
            for (byte b : bytes) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        }
    }

    static class FalsePositives {
        private Map<String, Object> handlers = new HashMap<>();
        private String status;
        private List<Object> events = new ArrayList<>();

        public Object fp01Delegator(String type) {
            handlers.put("encrypt", new Encryptor());
            handlers.put("decrypt", new Decryptor());
            handlers.put("hash", new Hasher());
            return handlers.getOrDefault(type, handlers.get("hash"));
        }

        public String fp02Getter() {
            return this.status;
        }

        public void fp03Setter(String value) {
            this.status = value;
        }

        public void fp04EventHandler(Object event) {
            this.events.add(event);
        }

        public Map<String, Object> fp05ConfigLoader() throws IOException {
            String content = new String(Files.readAllBytes(Paths.get("config.json")));
            return new Gson().fromJson(content, Map.class);
        }

        public String fp06WrapperSubprocess(String binary) throws IOException {
            Process p = Runtime.getRuntime().exec("ghidra_headless " + binary);
            BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
            return reader.lines().collect(Collectors.joining("\n"));
        }

        public Object fp07Factory(String analyzerType) {
            if (analyzerType.equals("static")) return new StaticAnalyzer();
            if (analyzerType.equals("dynamic")) return new DynamicAnalyzer();
            return new DefaultAnalyzer();
        }

        public Object fp08Router(String operation, byte[] data) {
            if (operation.equals("process")) return processor.handle(data);
            if (operation.equals("analyze")) return analyzer.run(data);
            return data;
        }

        public Object fp09ConditionalImport() {
            if (GPU_AVAILABLE) {
                return loadGpuDevice();
            }
            return "cpu";
        }

        public Map<String, String> fp10EnvConfig() {
            Map<String, String> config = new HashMap<>();
            config.put("apiKey", System.getenv("API_KEY"));
            config.put("debug", System.getenv("DEBUG"));
            return config;
        }

        public byte[] fp11Builder(String type) {
            if (type.equals("nop")) return new byte[]{(byte)0x90, (byte)0x90, (byte)0x90};
            if (type.equals("ret")) return new byte[]{(byte)0xC3};
            return new byte[0];
        }

        public void fp12Callback(String msg) {
            System.out.println("Message: " + msg);
        }

        private Processor processor;
        private Analyzer analyzer;
        private static final boolean GPU_AVAILABLE = false;

        private Object loadGpuDevice() {
            return null;
        }
    }

    static class ProductionCode {
        public String advancedKeygenRsa(String username, String productId) throws Exception {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair pair = keyGen.generateKeyPair();

            String dataToSign = username + ":" + productId;

            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(pair.getPrivate());
            signature.update(dataToSign.getBytes());
            byte[] signatureBytes = signature.sign();

            String licenseKey = Base64.getEncoder().encodeToString(signatureBytes);

            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            String checksum = bytesToHex(digest.digest(licenseKey.getBytes())).substring(0, 8);

            return licenseKey.substring(0, 20) + "-" + checksum;
        }

        public boolean safeBinaryPatcher(String binaryPath, List<Patch> patches) throws IOException {
            String backupPath = binaryPath + ".bak_" + System.currentTimeMillis();
            Files.copy(Paths.get(binaryPath), Paths.get(backupPath));

            byte[] data = Files.readAllBytes(Paths.get(binaryPath));

            for (Patch patch : patches) {
                int offset = indexOf(data, patch.pattern);
                if (offset == -1) {
                    return false;
                }

                System.arraycopy(patch.replacement, 0, data, offset, patch.replacement.length);
            }

            Files.write(Paths.get(binaryPath), data);
            return true;
        }

        public boolean licenseValidator(String licenseKey, String hardwareId) {
            if (licenseKey == null || licenseKey.length() < 20) {
                return false;
            }

            try {
                String[] parts = licenseKey.split("-");
                if (parts.length != 2) {
                    return false;
                }

                String signature = parts[0];
                String checksum = parts[1];

                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                String computed = bytesToHex(digest.digest(signature.getBytes())).substring(0, 8);

                if (!computed.equals(checksum)) {
                    return false;
                }

                Signature sig = Signature.getInstance("SHA256withRSA");
                sig.initVerify(publicKey);
                sig.update(hardwareId.getBytes());

                return sig.verify(Base64.getDecoder().decode(signature));
            } catch (Exception e) {
                return false;
            }
        }

        private String bytesToHex(byte[] bytes) {
            StringBuilder sb = new StringBuilder();
            for (byte b : bytes) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        }

        private int indexOf(byte[] array, byte[] target) {
            outer: for (int i = 0; i <= array.length - target.length; i++) {
                for (int j = 0; j < target.length; j++) {
                    if (array[i + j] != target[j]) {
                        continue outer;
                    }
                }
                return i;
            }
            return -1;
        }

        private PublicKey publicKey;
    }

    static class Encryptor {}
    static class Decryptor {}
    static class Hasher {}
    static class StaticAnalyzer {}
    static class DynamicAnalyzer {}
    static class DefaultAnalyzer {}
    static class Processor {
        public Object handle(byte[] data) { return null; }
    }
    static class Analyzer {
        public Object run(byte[] data) { return null; }
    }
    static class Patch {
        byte[] pattern;
        byte[] replacement;
    }
}
