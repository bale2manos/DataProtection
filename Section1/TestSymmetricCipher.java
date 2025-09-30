import java.util.Arrays;
import java.security.SecureRandom;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.concurrent.TimeUnit;

public class TestSymmetricCipher {

    public static void main(String[] args) {
        try {
            // 1️⃣ Generar una clave de 16 bytes (AES-128)
            byte[] key = new byte[16];
            SecureRandom random = new SecureRandom();
            random.nextBytes(key);

            System.out.println("Clave AES generada: " + bytesToHex(key));

            // 2️⃣ Crear instancia de SymmetricCipher (constructor sin argumentos)
            SymmetricCipher cipher = new SymmetricCipher();

            // 3️⃣ Texto de prueba
            String plainText = "¡Hola! Esto es un mensaje de prueba para AES CBC PKCS#5.";
            byte[] plaintextBytes = plainText.getBytes("UTF-8");
            System.out.println("Texto original: " + plainText);

            // 4️⃣ Encriptar
            byte[] encrypted = cipher.encryptCBC(plaintextBytes, key);
            System.out.println("Texto encriptado (hex): " + bytesToHex(encrypted));

            // 5️⃣ Desencriptar
            byte[] decrypted = cipher.decryptCBC(encrypted, key);
            String decryptedText = new String(decrypted, "UTF-8");
            System.out.println("Texto desencriptado: " + decryptedText);

            // Compare with OpenSSL (if available)
            try {
                byte[] opensslCipher = opensslEncrypt(cipher.addPadding(plaintextBytes), key,
                        "1234567890123456".getBytes("UTF-8"));
                System.out.println("OpenSSL encriptado (hex): " + bytesToHex(opensslCipher));
                if (Arrays.equals(encrypted, opensslCipher)) {
                    System.out.println("✅ Coincide con OpenSSL.");
                } else {
                    System.out.println("⚠️ No coincide con OpenSSL.");
                }
            } catch (Exception e) {
                System.out.println("OpenSSL no disponible o error al invocar: " + e.getMessage());
            }

            // 6️⃣ Verificación
            if (Arrays.equals(plaintextBytes, decrypted)) {
                System.out.println("✅ La desencriptación coincide con el texto original.");
            } else {
                System.out.println("❌ La desencriptación NO coincide con el texto original.");
            }

            // TESTS DE ARCHIVOS
            String[] files = { "test16.txt", "test64.txt", "testQuijote.txt" };
            for (String filename : files) {
                try {
                    java.nio.file.Path path = java.nio.file.Paths.get(filename);
                    byte[] original = java.nio.file.Files.readAllBytes(path);
                    System.out.println("\n--- Test archivo: " + filename + " ---");
                    System.out.println("Original: " + new String(original, "UTF-8"));
                    byte[] encryptedFile = cipher.encryptCBC(original, key);
                    System.out.println("Encriptado (hex): " + bytesToHex(encryptedFile));
                    byte[] decryptedFile = cipher.decryptCBC(encryptedFile, key);
                    String decryptedTextFile = new String(decryptedFile, "UTF-8");
                    System.out.println("Desencriptado: " + decryptedTextFile);
                    if (Arrays.equals(original, decryptedFile)) {
                        System.out.println("✅ La desencriptación coincide con el archivo original.");
                    } else {
                        System.out.println("❌ La desencriptación NO coincide con el archivo original.");
                    }

                    // Compare file encryption with OpenSSL
                    try {
                        byte[] opensslFileCipher = opensslEncrypt(cipher.addPadding(original), key,
                                "1234567890123456".getBytes("UTF-8"));
                        System.out.println("OpenSSL encriptado (hex): " + bytesToHex(opensslFileCipher));
                        if (Arrays.equals(encryptedFile, opensslFileCipher)) {
                            System.out.println("✅ Archivo: Coincide con OpenSSL.");
                        } else {
                            System.out.println("⚠️ Archivo: No coincide con OpenSSL.");
                        }
                    } catch (Exception e) {
                        System.out.println("OpenSSL no disponible o error al invocar (archivo): " + e.getMessage());
                    }
                } catch (Exception e) {
                    System.out.println("Error en test de archivo " + filename + ": " + e.getMessage());
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Método auxiliar para mostrar bytes en hexadecimal
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    // Convierte hex string a bytes
    private static byte[] hexToBytes(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    // Invoca OpenSSL para encriptar data usando AES-128-CBC con IV y KEY crudos
    // (sin salt)
    private static byte[] opensslEncrypt(byte[] data, byte[] key, byte[] iv) throws IOException, InterruptedException {
        // Prepare hex args for -K and -iv
        String keyHex = bytesToHex(key);
        String ivHex = bytesToHex(iv);

        ProcessBuilder pb = new ProcessBuilder("openssl", "enc", "-aes-128-cbc", "-K", keyHex, "-iv", ivHex, "-nosalt",
                "-nopad");
        pb.redirectErrorStream(true);
        Process p = null;
        try {
            p = pb.start();

            // Write data to stdin
            try (OutputStream os = p.getOutputStream()) {
                os.write(data);
                os.flush();
            }

            // Read stdout
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            try (InputStream is = p.getInputStream()) {
                byte[] buf = new byte[4096];
                int r;
                while ((r = is.read(buf)) != -1) {
                    baos.write(buf, 0, r);
                }
            }

            boolean exited = p.waitFor(10, TimeUnit.SECONDS);
            if (!exited) {
                p.destroyForcibly();
                throw new IOException("OpenSSL timed out");
            }

            int code = p.exitValue();
            if (code != 0) {
                String out = new String(baos.toByteArray(), "UTF-8");
                throw new IOException("OpenSSL failed (exit " + code + "): " + out);
            }

            byte[] result = baos.toByteArray();
            // OpenSSL with -nopad returns raw AES output; our Java implementation uses
            // PKCS#5 padding.
            // So if sizes differ, caller should be aware. We'll return raw bytes.
            return result;
        } finally {
            if (p != null)
                p.destroy();
        }
    }
}