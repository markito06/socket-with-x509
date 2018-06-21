import java.io.IOException;
import java.io.InputStreamReader;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.fips.FipsDRBG;
import org.bouncycastle.crypto.util.BasicEntropySourceProvider;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;

public abstract class SecurityClient {

	protected AesCipher aes;
	protected RsaCipher rsa;
	protected SecretKeyFactory pbkdf2;
	protected LeitorTerminal lerTerminal;

	private static final int PBKDF2_ITERATIONS = 1000;
	private static final int DERIVED_KEY_LENGTH = 128;

	static {

		Security.addProvider(new BouncyCastleFipsProvider());
		CryptoServicesRegistrar.setSecureRandom(FipsDRBG.SHA512_HMAC
				.fromEntropySource(new BasicEntropySourceProvider(new SecureRandom(), true)).build(null, false));

	}

	public SecurityClient() {
		lerTerminal = new LeitorTerminal(new InputStreamReader(System.in));
	}

	protected Key getDerivedKey(final char[] password) throws InvalidKeySpecException, NoSuchAlgorithmException {

		final SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
		final byte[] salt = new byte[16];
		sr.nextBytes(salt);

		return new SecretKeySpec(pbkdf2
				.generateSecret(new PBEKeySpec(password, salt, PBKDF2_ITERATIONS, DERIVED_KEY_LENGTH)).getEncoded(),
				"AES");
	}

	protected void chaves() throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException,
			BadPaddingException, InvalidKeySpecException, NoSuchAlgorithmException, IOException {
		final char[] sessionKey;
		final char[] publicKey = lerTerminal.readLine("Enter password : \n").toCharArray();
		final Key derivedKey = getDerivedKey(publicKey);
		aes.setKey(derivedKey);
		sessionKey = Hex.encodeHex(rsa.encrypt(derivedKey.getEncoded()));
		sendSessionKey(sessionKey);
	}
	
	

	protected abstract String getCommonName() throws IOException;
	
	protected abstract void sendSessionKey(char[] sessionKey);
	protected abstract Certificate receiveCertificateFromBob() throws CertificateException, DecoderException;
	protected abstract void fillFirstStep(X509Certificate cert) throws Exception;
	protected abstract void fillThirdStep() throws Exception;
	protected abstract String getBobNonce() throws Exception;
}
