import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class RsaCipher {

	   private final SecureRandom nonce;

		private final Cipher cipher;

		private PublicKey publicKey;
		private PrivateKey privateKey;

		public RsaCipher(final SecureRandom random) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {
			this.nonce = random;
			cipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA256AndMGF1Padding", "BCFIPS");
		}

		public byte[] encrypt(final byte[] content) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
			cipher.init(Cipher.ENCRYPT_MODE, publicKey, nonce);
			return cipher.doFinal(content);
		}

		public byte[] decrypt(final byte[] content) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
			cipher.init(Cipher.DECRYPT_MODE, privateKey, nonce);
			return cipher.doFinal(content);
		}

		public PublicKey getPublicKey() {
			return publicKey;
		}

		public void setPublicKey(final PublicKey publicKey) {
			this.publicKey = publicKey;
		}

		public void setPrivateKey(final PrivateKey privateKey) {
			this.privateKey = privateKey;
		}
}
