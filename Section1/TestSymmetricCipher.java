import java.util.Arrays;
import java.security.SecureRandom;

public class TestSymmetricCipher {

    public static void main(String[] args) {
        try {
            // 1️⃣ Generar una clave de 16 bytes (AES-128)
            byte[] key = new byte[16];
            SecureRandom random = new SecureRandom();
            random.nextBytes(key);

            System.out.println("Clave AES generada: " + bytesToHex(key));

            // 2️⃣ Crear instancia de SymmetricCipher
            SymmetricCipher cipher = new SymmetricCipher(key);

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

            // 6️⃣ Verificación
            if (Arrays.equals(plaintextBytes, decrypted)) {
                System.out.println("✅ La desencriptación coincide con el texto original.");
            } else {
                System.out.println("❌ La desencriptación NO coincide con el texto original.");
            }

            // TESTS DE ARCHIVOS
            String[] files = {"test16.txt", "test64.txt", "testQuijote.txt"};
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
}