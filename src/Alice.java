import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.PrintStream;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

public class Alice extends SecurityClient {

	Logger logger = Logger.getLogger(Alice.class.getName());
	private final int port;

	private Socket bob;
	private PrintStream out;
	private Scanner in;
	private FisrtStep fisrtStep =  new FisrtStep();

	public static void startClient(String ip, String porta) throws NoSuchAlgorithmException, NoSuchProviderException,
			NoSuchPaddingException, UnknownHostException, IOException, DecoderException, InvalidKeyException,
			InvalidKeySpecException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException,
			CertificateException, KeyStoreException, Exception {
		final Alice alice = new Alice(Integer.valueOf(porta));
		alice.connect(ip);
		alice.shutdown();
	}

	public Alice(final int port) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {

		this.port = port;

		pbkdf2 = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");

		final SecureRandom nonceAlice = new FixedRandom();
		aes = new AesCipher(nonceAlice);
		rsa = new RsaCipher(nonceAlice);
	}


	public void connect(String ip) throws IOException, CertificateException, DecoderException, InvalidKeySpecException,
			NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException,
			IllegalBlockSizeException, BadPaddingException, Exception {

		createSocket(ip);

		createInStream();

		createOutStream();

		X509Certificate cert = receiveCertificateFromBob();
		
		fillFirstStep(cert);

		super.chaves();

		do {
			
			String msg = lerTerminal.readLine("Enter msg to bob: \n");

			final char[] msgBytes = Hex.encodeHex(aes.encrypt(msg.getBytes()));

			logger.info("Encrypted msg: ");
			logger.info(Arrays.toString(msgBytes));

			out.println(msgBytes);

			final String encryptedMsg = in.nextLine();
			final String decryptedMsg = new String(aes.decrypt(Hex.decodeHex(encryptedMsg.toCharArray())));

			logger.info("Encrypted msg: ");
			logger.info(msg);
			
			logger.info("Decrypted msg: ");
			logger.info(decryptedMsg);

		} while (true);

	}

	public void shutdown() throws IOException {
		bob.close();
	}

	private Socket createSocket(String ip) throws IOException {
		bob = new Socket(ip, port);
		return bob;
	}

	private Scanner createInStream() throws IOException {
		in = new Scanner(bob.getInputStream());
		return in;
	}

	private PrintStream createOutStream() throws IOException {
		out = new PrintStream(bob.getOutputStream());
		return out;
	}

	@Override
	protected void sendSessionKey(final char[] sessionKey) {
		logger.info("Symmetrical key: ");
		logger.info(Arrays.toString(sessionKey));
		logger.info("Send key to Bob: ");
		out.println(sessionKey);
		logger.info("Key sended!");
	}
	
	@Override
	protected X509Certificate receiveCertificateFromBob() throws CertificateException, DecoderException {
		ObjectInputStream fromClient = null;
		byte[] x509FromBob = null;
		X509Certificate cert = null;
		try {
			fromClient = new ObjectInputStream(bob.getInputStream());
			x509FromBob = (byte[]) fromClient.readObject();

			cert = (X509Certificate) CertificateFactory.getInstance("X.509")
					.generateCertificate(new ByteArrayInputStream(x509FromBob));
			rsa.setPublicKey(cert.getPublicKey());

		} catch (Exception e) {
			logger.log(Level.SEVERE, "Failed to receive certificate", e);
			throw new CertificateException(e);
		}
		
		logger.info("Success on load certificate!");
		return cert;
	}


	@Override
	protected String getCommonName() throws IOException {
		return lerTerminal.readLine("Enter your common name : \n");
	}

	@Override
	protected void fillFirstStep(X509Certificate cert) throws Exception{
		X500Name x500Name = new JcaX509CertificateHolder(cert).getSubject(); 
		RDN cn = x500Name.getRDNs(BCStyle.CN)[0];
		fisrtStep.commonNameBob = cn.toString();
		
	}

	@Override
	protected void fillThirdStep() throws Exception {
		// TODO Auto-generated method stub
		
	}

	@Override
	protected String getBobNonce() throws Exception {
		// TODO Auto-generated method stub
		return null;
	}

}
