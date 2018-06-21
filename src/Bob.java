import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.PrintStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.operator.OperatorCreationException;

public class Bob extends SecurityServer {

	Logger logger = Logger.getLogger(Bob.class.getName());

	private final ServerSocket bob;
	private Socket alice;
	private PrintStream out;
	private Scanner in;
	private Key sessionKey;

	public static void startServer(String ipServer, String port)
			throws IOException, DecoderException, OperatorCreationException, GeneralSecurityException {
		final Bob bob = new Bob(Integer.valueOf(port), ipServer);
		bob.hear();
		bob.shutdown();
	}

	private Bob(final int porta, final String ipServer) throws NoSuchAlgorithmException, NoSuchProviderException,
			NoSuchPaddingException, IOException, OperatorCreationException, GeneralSecurityException {
		super();

		PublicKey publicKey = null;
		PrivateKey privateKey = null;

		certificate = certificateManager.getCertificate();
		privateKey = certificateManager.getPrivateKey();

		if (certificate == null || privateKey == null) {
			logger.info("Certificate not found");
			logger.info("Generate new cetificate");

			final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BCFIPS");

			final KeyPair keyParCa = keyPairGenerator.generateKeyPair();
			final KeyPair keyPar = keyPairGenerator.generateKeyPair();

			certificate = CertificateUtils.CertificadoAssinado(keyPar.getPublic(), keyParCa.getPrivate(),
					keyParCa.getPublic(), getCommonName());

			publicKey = certificate.getPublicKey();
			privateKey = keyPar.getPrivate();

			certificateManager.setCertificate(certificate);
			certificateManager.setPrivateKey(privateKey, certificate);
		}

		publicKey = certificate.getPublicKey();
		rsa.setPublicKey(publicKey);
		rsa.setPrivateKey(privateKey);

		InetAddress addr = InetAddress.getByName(ipServer);
		final int defaultMaxConnections = 50;
		bob = new ServerSocket(porta, defaultMaxConnections, addr);

	}

	private void hear()
			throws IOException, DecoderException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException,
			InvalidAlgorithmParameterException, KeyStoreException, NoSuchAlgorithmException, CertificateException {

		logger.info("Waiting for connection");
		alice = bob.accept();
		logger.info("Alice connected");

		in = new Scanner(alice.getInputStream());
		out = new PrintStream(alice.getOutputStream());

		ObjectOutputStream toServer = new ObjectOutputStream(alice.getOutputStream());
		final byte[] x509Encoded = certificate.getEncoded();

		logger.info("Send certificate: ");
		toServer.writeObject(x509Encoded);

		this.establishSession();

		while (in.hasNextLine()) {


			String encriptedMsg = in.nextLine();
			logger.info("Encrypted message received : " + encriptedMsg);

			String decriptedMsg = new String(aes.decrypt(Hex.decodeHex(encriptedMsg.toCharArray())));
			logger.info("Decrypted message : " + decriptedMsg);

		}

	}

	private void establishSession() throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException,
			InvalidAlgorithmParameterException, DecoderException {
		final String encryptedSessionKey = in.nextLine();
		logger.info("Encrypted session key from Alice:\n " + encryptedSessionKey);
		byte[] k = rsa.decrypt(Hex.decodeHex(encryptedSessionKey.toCharArray()));

		if (k == null || k.length == 0) {
			throw new InvalidKeyException("Session key is invalid!");
		}

		sessionKey = new SecretKeySpec(k, "AES");
		if (sessionKey == null) {
			throw new InvalidKeyException("Session key is invalid!");
		}
		
		aes.setKey(sessionKey);
		logger.info("Decrypted session key : \n" + sessionKey);
		logger.info("Established session!");
	}

	private void shutdown() throws IOException {

		bob.close();

		try {
			if (alice != null) {
				alice.close();
			}
			if (in != null) {
				throw new InException();
			}
			if (out != null) {
				throw new OutException();
			}

		} catch (InException e) {
			in.close();
			logger.log(Level.SEVERE, "No in", e);
		} catch (OutException e) {
			out.close();
			logger.log(Level.SEVERE, "No out", e);
		}

	}

	@Override
	public String getHomeFolder() {
		return System.getProperty("user.home");
	}

	@Override
	public String getFileName() {
		return "myCert.jks";
	}

	@Override
	public String getPassCa() throws IOException {
		return super.lerTerminal.readLine("Enter CA password: ");
	}

	@Override
	public String getPassCert() throws IOException {
		return super.lerTerminal.readLine("Enter your password: ");
	}

	@Override
	public String fillSecondStep() throws IOException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getCommonName() throws IOException {
		return super.lerTerminal.readLine("Enter bob common name:  \n");
	}

	@Override
	public String getAliceNonce() throws Exception {
		// TODO Auto-generated method stub
		return null;
	}
}
