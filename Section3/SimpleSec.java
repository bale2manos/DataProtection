import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import java.util.Scanner;

public class SimpleSec {

    private static RSALibrary rsa = new RSALibrary();
    private static Scanner scanner = new Scanner(System.in);

    public static void main(String[] args) {
        if (args.length < 1) {
            usageAndExit("No command provided.");
        }

        String command = args[0];

        try {
            switch (command) {
                case "g":
                    if (args.length != 1) {
                        usageAndExit("WARNING Command 'g' requires 0 arguments, but you provided " + (args.length - 1));
                    }
                    generateKeys();
                    break;
                case "e":
                    if (args.length != 3) {
                        usageAndExit(
                                "WARNING Command 'e' requires 2 arguments (sourceFile destinationFile), but you provided "
                                        + (args.length - 1));
                    }
                    encryptFile(args[1], args[2]);
                    break;
                case "d":
                    if (args.length != 3) {
                        usageAndExit(
                                "WARNING Command 'd' requires 2 arguments (sourceFile destinationFile), but you provided "
                                        + (args.length - 1));
                    }
                    decryptFile(args[1], args[2]);
                    break;
                default:
                    usageAndExit("WARNING Unknown command: " + command);
            }
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
            System.out.println("Reinicie la aplicación.");
        }
    }

    private static void usageAndExit(String message) {
        System.err.println("===== SimpleSec - Usage =====");
        System.err.println("  java SimpleSec g");
        System.err.println("  java SimpleSec e sourceFile destinationFile");
        System.err.println("  java SimpleSec d sourceFile destinationFile");
        if (message != null) {
            System.err.println(message);
        }
        System.exit(1);
    }

    /**
     * Command: g → Generate RSA keys, protect private.key with AES
     */
    // ---------------------- GENERATE KEYS ----------------------
    private static void generateKeys() throws Exception {
        // RSALibrary now returns the private key bytes; it still writes the public key.
        byte[] privateKeyBytes = rsa.generateKeys();
        System.out.println("RSA keys generated.");

        if (privateKeyBytes == null) {
            throw new IOException("Failed to generate RSA private key bytes.");
        }

        char[] pass = promptPassphrase();
        byte[] aesKey = new String(pass).getBytes("UTF-8");

        // Encrypt private key with AES/CBC and persist encrypted private.key
        SymmetricCipher sc = new SymmetricCipher();
        byte[] encPriv = sc.encryptCBC(privateKeyBytes, aesKey);
        Files.write(Paths.get("private.key"), encPriv);

        System.out.println("Private key encrypted with AES/CBC.");
    }

    // ---------------------- ENCRYPT ----------------------
    private static void encryptFile(String sourceFile, String destFile) throws Exception {
        // Read plaintext
        byte[] plain = Files.readAllBytes(Paths.get(sourceFile));

        // Load private key
        char[] pass = promptPassphrase();
        byte[] aesKey = new String(pass).getBytes("UTF-8");
        byte[] encPriv = Files.readAllBytes(Paths.get("private.key"));
        SymmetricCipher sc = new SymmetricCipher();
        PrivateKey priv = null;

        try {
            byte[] privBytes = sc.decryptCBC(encPriv, aesKey);
            priv = loadPrivateKey(privBytes);
        } catch (Exception ex) {
            throw new SecurityException(
                    "WARNING: incorrect passphrase : couldn't decypher the private key.\n"

            );
        }

        // Load public key
        byte[] pubBytes = Files.readAllBytes(Paths.get("public.key"));
        PublicKey pub = loadPublicKey(pubBytes);

        // Generate session key (16 bytes)
        byte[] sessionKey = new byte[16];
        SecureRandom sr = new SecureRandom();
        sr.nextBytes(sessionKey);

        // Encrypt plaintext with AES/CBC
        byte[] ciphertext = sc.encryptCBC(plain, sessionKey);

        // Encrypt session key with public key RSA
        byte[] encSessionKey = rsa.encrypt(sessionKey, pub);

        // Sign ciphertext with RSA private key
        byte[] signature = rsa.sign(ciphertext, priv);

        // Write concatenated file: [encSessionKey][ciphertext][signature]
        try (FileOutputStream fos = new FileOutputStream(destFile)) {
            fos.write(encSessionKey);
            fos.write(ciphertext);
            fos.write(signature);
        }

        System.out.println("File encrypted and signed successfully.");
    }

    // ---------------------- DECRYPT ----------------------
    private static void decryptFile(String sourceFile, String destFile) throws Exception {
        byte[] fileData = Files.readAllBytes(Paths.get(sourceFile));
        // debemos recibir [encSessionKey][ciphertext][signature] la signature son 128 y
        // el encSessionKey otros 128
        if (fileData.length < 128 + 128) {
            throw new SecurityException("Archivo corrupto o demasiado pequeño.");
        }
        // 1. The input encrypted text is divided in two parts: the encrypted text
        // corresponding to the session key and the encrypted text corresponding to the
        // original plaintext.
        // Extract encrypted session key (128 bytes)
        byte[] encSessionKey = new byte[128];
        System.arraycopy(fileData, 0, encSessionKey, 0, 128);

        // Extract signature (128 bytes at the end)
        byte[] signature = new byte[128];
        System.arraycopy(fileData, fileData.length - 128, signature, 0, 128);

        // Extract ciphertext (rest of the file)
        byte[] ciphertext = new byte[fileData.length - 128 - 128];
        System.arraycopy(fileData, 128, ciphertext, 0, ciphertext.length);
        // 2. Decryption of the session key. For this decryption the asymmetric
        // algorithm RSA will be used with the RSA private key of the user.
        // The application will prompt the user for the passphrase necessary to retrieve
        // the private RSA key.
        char[] pass = promptPassphrase();
        byte[] aesKey = new String(pass).getBytes("UTF-8");
        byte[] encPriv = Files.readAllBytes(Paths.get("private.key"));
        SymmetricCipher sc = new SymmetricCipher();
        PrivateKey priv = null;

        try {
            byte[] privBytes = sc.decryptCBC(encPriv, aesKey);
            priv = loadPrivateKey(privBytes);
        } catch (Exception ex) {
            throw new SecurityException(
                    "WARNING: incorrect passphrase : couldn't decypher the private key.\n"

            );
        }

        // Load public key
        byte[] pubBytes = Files.readAllBytes(Paths.get("public.key"));
        PublicKey pub = loadPublicKey(pubBytes);

        // Decrypt session key
        byte[] sessionKey = rsa.decrypt(encSessionKey, priv);

        // Verify signature
        if (!rsa.verify(ciphertext, signature, pub)) {
            throw new SecurityException("Signature verification failed! Archivo corrupto o modificado.");
        }
        // 3. Decryption of the encrypted text, using the symmetric decryption algorithm
        // AES in CBC mode of operation. For the decryption process the AES key obtained
        // as the result of the step 2 will be used.
        // Decrypt AES/CBC
        byte[] plain = sc.decryptCBC(ciphertext, sessionKey);

        // Write plaintext to destination
        Files.write(Paths.get(destFile), plain);

        System.out.println("File decrypted and signature verified successfully.");
    }

    // ---------------------- PASS PHRASE ----------------------
    private static char[] promptPassphrase() throws IOException {
        System.out.print("Enter 16-character passphrase: ");
        String pass = scanner.nextLine();
        if (pass.length() != 16) { // We force the length to be 16
            throw new IllegalArgumentException(
                    "Passphrase must be exactly 16 characters. Try again after restarting the app");
        }
        return pass.toCharArray();
    }

    // ---------------------- HELPER METHODS ----------------------
    private static PrivateKey loadPrivateKey(byte[] keyBytes) throws Exception {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    private static PublicKey loadPublicKey(byte[] keyBytes) throws Exception {
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }
}
