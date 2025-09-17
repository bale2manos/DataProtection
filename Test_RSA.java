import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.nio.charset.StandardCharsets;

public class Test_RSA {
	
	public static void main(String[] args) throws Exception {
		RSALibrary r = new RSALibrary();
		r.generateKeys();
		
		/* Read  public key*/
		Path path = Paths.get("./public.key");
		byte[] bytes = Files.readAllBytes(path);
		//Public key is stored in x509 format
		X509EncodedKeySpec keyspec = new X509EncodedKeySpec(bytes);
		KeyFactory keyfactory = KeyFactory.getInstance("RSA");
		PublicKey publicKey = keyfactory.generatePublic(keyspec);
		
		/* Read private key */
		path = Paths.get("./private.key");
		byte[] bytes2 = Files.readAllBytes(path);
		//Private key is stored in PKCS8 format
		PKCS8EncodedKeySpec keyspec2 = new PKCS8EncodedKeySpec(bytes2);
		KeyFactory keyfactory2 = KeyFactory.getInstance("RSA");
		PrivateKey privateKey = keyfactory2.generatePrivate(keyspec2);




        String mensaje = "Esto es un mensaje de prueba con RSA.";
		System.out.println("Mensaje original: " + mensaje);

		// --- Cifrado y descifrado ---
		byte[] cifrado = r.encrypt(mensaje.getBytes(StandardCharsets.UTF_8), publicKey);
		System.out.println("Cifrado (bytes): " + cifrado.length);

		byte[] descifrado = r.decrypt(cifrado, privateKey);
		System.out.println("Descifrado: " + new String(descifrado, StandardCharsets.UTF_8));

		// --- Firma y verificación ---
		byte[] firma = r.sign(mensaje.getBytes(StandardCharsets.UTF_8), privateKey);
		System.out.println("Firma generada (bytes): " + firma.length);

		boolean verificado = r.verify(mensaje.getBytes(StandardCharsets.UTF_8), firma, publicKey);
		System.out.println("¿Firma verificada?: " + verificado);
	}	
    

	
}