import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

public class AesCipher {

	private static final int IV_LENGTH = 16;

	private final Cipher cipher;
	private final byte[] iv = new byte[IV_LENGTH];

	private Key key;

	public AesCipher(final SecureRandom random) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {
		random.nextBytes(iv);
		cipher = Cipher.getInstance("AES/GCM/NoPadding", "BCFIPS");
	}

	public byte[] encrypt(final byte[] content) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
		return cipher.doFinal(content);
	}

	public byte[] decrypt(final byte[] content) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
		cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
		return cipher.doFinal(content);
	}

	public void setKey(final Key key) {
		this.key = key;
	}

}
