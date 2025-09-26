import java.io.*;
import java.nio.file.*;
import java.nio.file.attribute.FileTime;
import java.util.*;

public class TestSimpleSec {

    private static final Path WORKDIR = Paths.get(".");

    public static void main(String[] args) throws Exception {
        System.out.println("Running SimpleSec tests...");
        cleanup();

        runTest("generateKeys_valid", TestSimpleSec::testGenerateKeysValid);
        runTest("generateKeys_invalidLength", TestSimpleSec::testGenerateKeysInvalidLength);
        runTest("encrypt_nonexistent_source", TestSimpleSec::testEncryptNonexistent);
        runTest("encrypt_decrypt_flow", TestSimpleSec::testEncryptDecryptFlow);
        runTest("decrypt_modified_signature", TestSimpleSec::testDecryptModifiedSignature);
        runTest("decrypt_wrong_passphrase", TestSimpleSec::testDecryptWrongPassphrase);
        runTest("decrypt_too_small_file", TestSimpleSec::testDecryptTooSmallFile);
        runTest("generateKeys_overwrite", TestSimpleSec::testGenerateKeysOverwrite);
        runTest("encrypt_empty_file", TestSimpleSec::testEncryptEmptyFile);
        runTest("decrypt_truncated_signature", TestSimpleSec::testDecryptTruncatedSignature);
        runTest("encrypt_destination_invalid", TestSimpleSec::testEncryptDestinationInvalid);
        runTest("encrypt_without_keys", TestSimpleSec::testEncryptWithoutKeys);

        System.out.println("\nAll tests completed.");
    }

    @FunctionalInterface
    private interface TestAction {
        void run() throws Exception;
    }

    private static void runTest(String name, TestAction test) {
        System.out.println("\n--- " + name + " ---");
        try {
            test.run();
            System.out.println(name + ": PASS");
        } catch (AssertionError ae) {
            System.out.println(name + ": FAIL -> " + ae.getMessage());
        } catch (Exception e) {
            System.out.println(name + ": ERROR -> " + e.getMessage());
        }
    }

    private static void cleanup() throws IOException {
        Files.deleteIfExists(WORKDIR.resolve("public.key"));
        Files.deleteIfExists(WORKDIR.resolve("private.key"));
        Files.deleteIfExists(WORKDIR.resolve("plaintext.tmp"));
        Files.deleteIfExists(WORKDIR.resolve("ciphered.tmp"));
        Files.deleteIfExists(WORKDIR.resolve("deciphered.tmp"));
    }

    // Helper to run SimpleSec with optional stdin input (passphrase)
    // removed unused convenience wrapper

    private static ProcessResult runSimpleSecWithInput(String input, String... cmdAndArgs) throws Exception {
        ProcessBuilder pb = new ProcessBuilder();
        List<String> cmd = new ArrayList<>();
        cmd.add("java");
        cmd.addAll(Arrays.asList(cmdAndArgs));
        pb.command(cmd);
        pb.directory(new File("."));
        pb.redirectErrorStream(true);
        Process p = pb.start();
        if (input != null) {
            try (OutputStream os = p.getOutputStream()) {
                os.write((input + System.lineSeparator()).getBytes("UTF-8"));
                os.flush();
            }
        } else {
            p.getOutputStream().close();
        }
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (InputStream is = p.getInputStream()) {
            byte[] buf = new byte[4096];
            int r;
            while ((r = is.read(buf)) != -1) {
                baos.write(buf, 0, r);
            }
        }
        int exit = p.waitFor();
        String out = new String(baos.toByteArray(), "UTF-8");
        return new ProcessResult(exit, out);
    }

    // Tests
    private static void testGenerateKeysValid() throws Exception {
        // 16-char passphrase
        ProcessResult r = runSimpleSecWithInput("0123456789ABCDEF", "SimpleSec", "g");
        String out = r.output;
        assert out.contains("RSA keys generated.") : "expected RSA keys generated message";
        assert Files.exists(Paths.get("public.key")) : "public.key missing";
        assert Files.exists(Paths.get("private.key")) : "private.key missing";
        long size = Files.size(Paths.get("private.key"));
        assert size > 0 : "private.key empty";
    }

    private static void testGenerateKeysInvalidLength() throws Exception {
        // short passphrase
        ProcessResult r = runSimpleSecWithInput("short", "SimpleSec", "g");
        String out = r.output;
        assert out.contains("Passphrase must be exactly 16 characters") : "did not detect invalid passphrase length";
    }

    private static void testEncryptNonexistent() throws Exception {
        // assume keys exist from previous valid test
        ProcessResult r = runSimpleSecWithInput("0123456789ABCDEF", "SimpleSec", "e", "no_such_file.txt", "out.tmp");
        String out = r.output;
        // Expect non-zero exit or error message mentioning NoSuchFile
        assert (r.exitCode != 0) || out.toLowerCase().contains("nosuchfile")
                || out.toLowerCase().contains("no such file") : "expected failure for nonexistent source file";
    }

    private static void testEncryptDecryptFlow() throws Exception {
        // write plaintext (use unique filenames to avoid interference)
        String id = UUID.randomUUID().toString().substring(0, 8);
        Path plainPath = Paths.get("plaintext_" + id + ".tmp");
        Path cipherPath = Paths.get("ciphered_" + id + ".tmp");
        Path decPath = Paths.get("deciphered_" + id + ".tmp");
        String text = "Mensaje de prueba para encrypt/decrypt flow.";
        Files.write(plainPath, text.getBytes("UTF-8"));
        // Encrypt
        // Ensure fresh keys for this isolated test
        ProcessResult rGen = runSimpleSecWithInput("0123456789ABCDEF", "SimpleSec", "g");
        if (rGen.exitCode != 0)
            throw new AssertionError("generateKeys failed: " + rGen.output);

        ProcessResult rEnc = runSimpleSecWithInput("0123456789ABCDEF", "SimpleSec", "e", plainPath.toString(),
                cipherPath.toString());
        if (rEnc.exitCode != 0) {
            throw new AssertionError("encrypt failed (exit=" + rEnc.exitCode + "): " + rEnc.output);
        }
        // Wait up to 2s for ciphered file to appear (handle small race conditions)
        boolean seenCipher = waitForFile(cipherPath, 2000);
        assert seenCipher : cipherPath + " not created";
        long cipherSize = Files.size(cipherPath);
        assert cipherSize > 0 : cipherPath + " empty";

        // Decrypt
        ProcessResult rDec = runSimpleSecWithInput("0123456789ABCDEF", "SimpleSec", "d", cipherPath.toString(),
                decPath.toString());
        if (rDec.exitCode != 0) {
            throw new AssertionError("decrypt failed (exit=" + rDec.exitCode + "):\nENC_OUT=\n" + rEnc.output
                    + "\nDEC_OUT=\n" + rDec.output);
        }
        // Wait up to 2s for deciphered file to appear
        boolean seenDec = waitForFile(decPath, 2000);
        if (!seenDec) {
            StringBuilder diag = new StringBuilder();
            diag.append("deciphered.tmp not created\n");
            diag.append("--- ENC output ---\n").append(rEnc.output).append("\n");
            diag.append("--- DEC output ---\n").append(rDec.output).append("\n");
            diag.append("--- Directory listing ---\n");
            try {
                Files.list(Paths.get(".")).filter(Files::isRegularFile).forEach(p -> {
                    try {
                        diag.append(p.getFileName()).append(" : ").append(Files.size(p)).append(" bytes\n");
                    } catch (Exception e) {
                        diag.append(p.getFileName()).append(" : (error getting size)\n");
                    }
                });
            } catch (Exception e) {
                diag.append("(failed to list dir: " + e.getMessage() + ")\n");
            }
            throw new AssertionError(diag.toString());
        }
        String out = new String(Files.readAllBytes(decPath), "UTF-8");
        if (!out.equals(text)) {
            String diag = String.format("decrypted length=%d, expected=%d, decrypted=%s", out.length(), text.length(),
                    out);
            throw new AssertionError("decrypted content does not match original: " + diag + "\nENC_OUT=\n" + rEnc.output
                    + "\nDEC_OUT=\n" + rDec.output);
        }
        // cleanup
        Files.deleteIfExists(plainPath);
        Files.deleteIfExists(cipherPath);
        Files.deleteIfExists(decPath);
    }

    private static void testDecryptModifiedSignature() throws Exception {
        // create a fresh ciphered file to test
        String id = UUID.randomUUID().toString().substring(0, 8);
        Path plain = Paths.get("plain_mod_" + id + ".tmp");
        Path cipher = Paths.get("cipher_mod_" + id + ".tmp");
        Files.write(plain, "texto para firma corrupta".getBytes("UTF-8"));
        ProcessResult rEnc = runSimpleSecWithInput("0123456789ABCDEF", "SimpleSec", "e", plain.toString(),
                cipher.toString());
        if (rEnc.exitCode != 0)
            throw new AssertionError("encrypt for modified-sign test failed: " + rEnc.output);
        // corrupt last byte (signature at end)
        byte[] data = Files.readAllBytes(cipher);
        if (data.length < 256)
            throw new AssertionError("cipher too small for this test");
        data[data.length - 1] = (byte) (data[data.length - 1] ^ 0xFF);
        Files.write(cipher, data, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING);

        ProcessResult r = runSimpleSecWithInput("0123456789ABCDEF", "SimpleSec", "d", cipher.toString(),
                "deciphered_mod_" + id + ".tmp");
        String out = r.output;
        assert out.contains("Signature verification failed") || out.contains("Archivo corrupto")
                : "expected signature verification failure";
        Files.deleteIfExists(plain);
        Files.deleteIfExists(cipher);
        Files.deleteIfExists(Paths.get("deciphered_mod_" + id + ".tmp"));
    }

    private static void testDecryptWrongPassphrase() throws Exception {
        // create a fresh ciphered file
        String id = UUID.randomUUID().toString().substring(0, 8);
        Path plain = Paths.get("plain_wp_" + id + ".tmp");
        Path cipher = Paths.get("cipher_wp_" + id + ".tmp");
        Files.write(plain, "texto para passphrase err".getBytes("UTF-8"));
        ProcessResult rEnc = runSimpleSecWithInput("0123456789ABCDEF", "SimpleSec", "e", plain.toString(),
                cipher.toString());
        if (rEnc.exitCode != 0)
            throw new AssertionError("encrypt for wrong-pass test failed: " + rEnc.output);

        // try decrypt with wrong passphrase
        ProcessResult r = runSimpleSecWithInput("WRONG-PASSPHRASE!!", "SimpleSec", "d", cipher.toString(),
                "dec_out_wp_" + id + ".tmp");
        String out = r.output;
        assert out.contains("couldn't decypher the private key") || out.toLowerCase().contains("incorrect passphrase")
                : "expected incorrect passphrase handling";
        Files.deleteIfExists(plain);
        Files.deleteIfExists(cipher);
        Files.deleteIfExists(Paths.get("dec_out_wp_" + id + ".tmp"));
    }

    private static void testDecryptTooSmallFile() throws Exception {
        // create tiny file
        Files.write(Paths.get("tiny.bin"), new byte[10]);
        ProcessResult r = runSimpleSecWithInput("0123456789ABCDEF", "SimpleSec", "d", "tiny.bin", "out.bin");
        String out = r.output;
        assert out.contains("Archivo corrupto o demasiado pequeño") : "expected too small file error";
    }

    private static void testGenerateKeysOverwrite() throws Exception {
        // generate once
        ProcessResult r1 = runSimpleSecWithInput("0123456789ABCDEF", "SimpleSec", "g");
        if (r1.exitCode != 0)
            throw new AssertionError("first generate failed: " + r1.output);
        Path pub = Paths.get("public.key");
        Path priv = Paths.get("private.key");
        assert Files.exists(pub) && Files.exists(priv) : "keys missing after first generate";
        FileTime t1 = Files.getLastModifiedTime(pub);

        // wait a bit to ensure mtime changes on regenerate
        Thread.sleep(200);

        ProcessResult r2 = runSimpleSecWithInput("0123456789ABCDEF", "SimpleSec", "g");
        if (r2.exitCode != 0)
            throw new AssertionError("second generate failed: " + r2.output);
        FileTime t2 = Files.getLastModifiedTime(pub);
        assert t2.toMillis() >= t1.toMillis() : "public.key not updated on regenerate";
    }

    private static void testEncryptEmptyFile() throws Exception {
        String id = UUID.randomUUID().toString().substring(0, 8);
        Path plain = Paths.get("empty_" + id + ".tmp");
        Path cipher = Paths.get("empty_cipher_" + id + ".tmp");
        Path dec = Paths.get("empty_dec_" + id + ".tmp");
        Files.write(plain, new byte[0]);
        // ensure keys exist
        ProcessResult rGen = runSimpleSecWithInput("0123456789ABCDEF", "SimpleSec", "g");
        if (rGen.exitCode != 0)
            throw new AssertionError("generateKeys failed: " + rGen.output);

        ProcessResult rEnc = runSimpleSecWithInput("0123456789ABCDEF", "SimpleSec", "e", plain.toString(),
                cipher.toString());
        if (rEnc.exitCode != 0)
            throw new AssertionError("encrypt empty failed: " + rEnc.output);
        assert Files.size(cipher) > 0 : "cipher for empty file is empty";

        ProcessResult rDec = runSimpleSecWithInput("0123456789ABCDEF", "SimpleSec", "d", cipher.toString(),
                dec.toString());
        if (rDec.exitCode != 0)
            throw new AssertionError("decrypt empty failed: " + rDec.output);

        byte[] got = Files.readAllBytes(dec);
        assert got.length == 0 : "decrypted empty file not empty";

        Files.deleteIfExists(plain);
        Files.deleteIfExists(cipher);
        Files.deleteIfExists(dec);
    }

    private static void testDecryptTruncatedSignature() throws Exception {
        // create a fresh ciphered file and then truncate the signature entirely
        String id = UUID.randomUUID().toString().substring(0, 8);
        Path plain = Paths.get("plain_trunc_" + id + ".tmp");
        Path cipher = Paths.get("cipher_trunc_" + id + ".tmp");
        Files.write(plain, "texto para trunc signature".getBytes("UTF-8"));
        ProcessResult rEnc = runSimpleSecWithInput("0123456789ABCDEF", "SimpleSec", "e", plain.toString(),
                cipher.toString());
        if (rEnc.exitCode != 0)
            throw new AssertionError("encrypt for trunc-sign test failed: " + rEnc.output);
        byte[] data = Files.readAllBytes(cipher);
        if (data.length < 256) {
            // If the cipher is smaller than minimum possible (encSessionKey + signature),
            // expect decrypt to report corrupt/small
            ProcessResult r = runSimpleSecWithInput("0123456789ABCDEF", "SimpleSec", "d", cipher.toString(),
                    "dec_trunc_" + id + ".tmp");
            String out = r.output;
            assert out.contains("Archivo corrupto o demasiado pequeño") || out.toLowerCase().contains("corrupt")
                    || out.toLowerCase().contains("too small") : "expected too-small handling for tiny cipher";
        } else {
            // remove last 128 bytes (signature)
            byte[] truncated = new byte[data.length - 128];
            System.arraycopy(data, 0, truncated, 0, truncated.length);
            Files.write(cipher, truncated, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING);

            ProcessResult r = runSimpleSecWithInput("0123456789ABCDEF", "SimpleSec", "d", cipher.toString(),
                    "dec_trunc_" + id + ".tmp");
            String out = r.output;
            // Expect corrupt/too small message or signature verification failure
            assert out.contains("Archivo corrupto o demasiado pequeño") || out.contains("Signature verification failed")
                    || out.toLowerCase().contains("corrupt") : "expected truncated-sign handling";
        }
        Files.deleteIfExists(plain);
        Files.deleteIfExists(cipher);
        Files.deleteIfExists(Paths.get("dec_trunc_" + id + ".tmp"));
    }

    private static void testEncryptDestinationInvalid() throws Exception {
        // ensure keys
        ProcessResult rGen = runSimpleSecWithInput("0123456789ABCDEF", "SimpleSec", "g");
        if (rGen.exitCode != 0)
            throw new AssertionError("generateKeys failed: " + rGen.output);
        Path plain = Paths.get("plain_dest_invalid.tmp");
        Files.write(plain, "test".getBytes("UTF-8"));
        // destination in nonexistent directory
        ProcessResult r = runSimpleSecWithInput("0123456789ABCDEF", "SimpleSec", "e", plain.toString(),
                "no_dir/out.bin");
        String out = r.output;
        assert r.exitCode != 0 || out.toLowerCase().contains("no such file") || out.toLowerCase().contains("cannot")
                || out.toLowerCase().contains("error") : "expected failure writing to invalid destination";
        Files.deleteIfExists(plain);
    }

    private static void testEncryptWithoutKeys() throws Exception {
        // remove keys if present
        Files.deleteIfExists(Paths.get("public.key"));
        Files.deleteIfExists(Paths.get("private.key"));
        Path plain = Paths.get("plain_nokeys.tmp");
        Files.write(plain, "hello".getBytes("UTF-8"));
        ProcessResult r = runSimpleSecWithInput("0123456789ABCDEF", "SimpleSec", "e", plain.toString(),
                "out_nokeys.tmp");
        String out = r.output;
        assert r.exitCode != 0 || out.toLowerCase().contains("public.key") || out.toLowerCase().contains("private.key")
                || out.toLowerCase().contains("no such file") : "expected failure when keys missing";
        Files.deleteIfExists(plain);
        Files.deleteIfExists(Paths.get("out_nokeys.tmp"));
    }

    // Simple structure for subprocess result
    private static class ProcessResult {
        int exitCode;
        String output;

        ProcessResult(int exitCode, String output) {
            this.exitCode = exitCode;
            this.output = output;
        }
    }

    // Wait for a file to exist within timeoutMillis. Returns true if file exists
    // within timeout.
    private static boolean waitForFile(Path path, int timeoutMillis) throws InterruptedException {
        int waited = 0;
        int step = 50;
        while (waited < timeoutMillis) {
            if (Files.exists(path))
                return true;
            Thread.sleep(step);
            waited += step;
        }
        return Files.exists(path);
    }
}
