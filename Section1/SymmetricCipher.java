import java.io.FileDescriptor;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import javax.crypto.*;

public class SymmetricCipher {

	byte[] byteKey;
	SymmetricEncryption s;
	SymmetricEncryption d;
	int blockSize  = 16;  
	
	// Initialization Vector (fixed)
	
	byte[] iv = new byte[] { (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54, 
		(byte)55, (byte)56, (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52,
		(byte)53, (byte)54};

	/*************************************************************************************/
	/* Constructor method */
	/*************************************************************************************/
	public SymmetricCipher() {
		this.byteKey = null;
		this.s = null;
		this.d = null;
	}

    /*************************************************************************************/
	/* Method to encrypt using AES/CBC/PKCS5 */
    /*************************************************************************************/
	public byte[] addPadding(byte[] input) {
		int paddingLength = blockSize - (input.length % blockSize);
		byte[] paddedInput = new byte[input.length + paddingLength];
		System.arraycopy(input, 0, paddedInput, 0, input.length);
		for (int i = input.length; i < paddedInput.length; i++) {
			paddedInput[i] = (byte) paddingLength;
		}
		return paddedInput;
	}

	public byte[] removePadding(byte[] input) {
		int paddingLength = input[input.length - 1];
		byte[] unpaddedInput = new byte[input.length - paddingLength];
		System.arraycopy(input, 0, unpaddedInput, 0, unpaddedInput.length);
		return unpaddedInput;
	}


	public byte[] encryptCBC (byte[] input, byte[] byteKey) throws Exception {	
		try {
			s = new SymmetricEncryption(byteKey);
		} catch (Exception e) {
			e.printStackTrace();
		}

		
		byte[] plaintext = addPadding(input);// Generate the plaintext with padding --llamar al padding
		byte[] ciphertext = new byte[plaintext.length];
        byte[] xorAux = new byte[blockSize];
        byte[] ci = new byte[iv.length];
        System.arraycopy(iv, 0, ci, 0, iv.length);
        for (int i = 0; i < plaintext.length; i += blockSize) {
            for (int j = 0; j < blockSize; j++) {
                xorAux[j] = (byte) (plaintext[i + j] ^ ci[j]); // XOR con casting byte a byte
            }
            byte[] encryptedBlock = s.encryptBlock(xorAux);
            System.arraycopy(encryptedBlock, 0, ciphertext, i, blockSize);

            ci = encryptedBlock; //c_{i-1}
        }
                    
		
		
		return ciphertext;
	}
	
	/*************************************************************************************/
	/* Method to decrypt using AES/CBC/PKCS5 */
    /*************************************************************************************/
	
	
	public byte[] decryptCBC (byte[] input, byte[] byteKey) throws Exception {
		try {
			d = new SymmetricEncryption(byteKey);
		} catch (Exception e) {
			e.printStackTrace();
		}

		
		byte[] plaintext = new byte[input.length];
        byte[] ti = new byte[blockSize]; //t_{i-1}
        System.arraycopy(iv, 0, ti, 0, blockSize);
			
		// Generate the plaintext
		for (int i = 0; i < input.length; i += blockSize) {
            byte[] currentBlock = new byte[blockSize];
            System.arraycopy(input, i, currentBlock, 0, blockSize);

            byte[] decryptedBlock = d.decryptBlock(currentBlock);

            for (int j = 0; j < blockSize; j++) {
                plaintext[i + j] = (byte) (decryptedBlock[j] ^ ti[j]);
            }
            System.arraycopy(currentBlock, 0, ti, 0, blockSize);
        }

		
		// Eliminate the padding
		return removePadding(plaintext);
	}
	
}
