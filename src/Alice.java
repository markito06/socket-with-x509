import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.PrintStream;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.fips.FipsDRBG;
import org.bouncycastle.crypto.util.BasicEntropySourceProvider;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;


public class Alice {

	 static {

	        Security.addProvider(new BouncyCastleFipsProvider());
	        CryptoServicesRegistrar.setSecureRandom(FipsDRBG.SHA512_HMAC.fromEntropySource(new BasicEntropySourceProvider(new SecureRandom(), true)).build(null, false));

	    }

	    public static void startClient(String ip, String porta)
	            throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, UnknownHostException, IOException, DecoderException, InvalidKeyException,
	            InvalidKeySpecException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, CertificateException, KeyStoreException {
	        final Alice client = new Alice(Integer.valueOf(porta));
	        client.conectar(ip);
	        client.desligar();
	    }

	    private static final int PBKDF2_ITERATIONS = 1000;
	    private static final int DERIVED_KEY_LENGTH = 128;

	    private final int port;

	    private final CifradorAES aes;
	    private final CifradorRSA rsa;

	    private final SecretKeyFactory pbkdf2;

	    private Socket server;
	    private PrintStream out;
	    private Scanner in;

	    public Alice(final int port) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {

	        this.port = port;

	        pbkdf2 = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");

	        final SecureRandom random = new FixedRandom();
	        aes = new CifradorAES(random);
	        rsa = new CifradorRSA(random);
	    }

	    private Key ChaveDerivada(final char[] password) throws InvalidKeySpecException, NoSuchAlgorithmException {

	        final SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
	        final byte[] salt = new byte[16];
	        sr.nextBytes(salt);

	        return new SecretKeySpec(pbkdf2.generateSecret(new PBEKeySpec(password, salt, PBKDF2_ITERATIONS, DERIVED_KEY_LENGTH)).getEncoded(), "AES");
	    }

	    @SuppressWarnings("resource")
		public void conectar(String ip) throws IOException, CertificateException, DecoderException, InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {

	        criadorSocket(ip);

	        criadorInStream();

	        criadorOutStream();

	        criarCertificado();

	        chaves();

	        do {
	            ReaderWithInfo escrever = new ReaderWithInfo(new InputStreamReader(System.in));
	            String msg = escrever.readLine("Digite msg: ");
	            
	            final char[] enviado = Hex.encodeHex(aes.encrypt(msg.getBytes()));
	            
	            System.out.println("\nMensagem codificada\n");
	            System.out.println(Arrays.toString(enviado));

	            out.println(enviado);

	            final String recebido = in.nextLine();
	            final String descriptografado = new String(aes.decrypt(Hex.decodeHex(recebido.toCharArray())));

	            System.out.println("\nMensagem Recebida\n");
	            System.out.println("\nMensagem texto plano\n");
	            System.out.print(msg);
	            System.out.println("\nMensagem codificada\n");
	            System.out.println(descriptografado);

	        } while (true);

	    }

	    public void desligar() throws IOException {
	        server.close();
	    }

	    private Socket criadorSocket(String ip) throws IOException {
	        server = new Socket(ip, port);
	        return server;
	    }

	    private Scanner criadorInStream() throws IOException {
	        in = new Scanner(server.getInputStream());
	        return in;
	    }

	    private PrintStream criadorOutStream() throws IOException {
	        out = new PrintStream(server.getOutputStream());
	        return out;
	    }

	    private void enviarChaveSimetrica(final char[] chaveSimetrica) {
	    	System.out.println("Chave simetrica : ");
	        System.out.println(Arrays.toString(chaveSimetrica));
	        out.println(chaveSimetrica);
	        System.out.println("Chave simetrica enviada");
	    }

	    private void criarCertificado() throws CertificateException, DecoderException {
	    	ObjectInputStream fromClient = null;
	    	byte [] certificadoRecebido = null;
	    	try {
	    		 fromClient = new ObjectInputStream(server.getInputStream());
	    		 certificadoRecebido = (byte[]) fromClient.readObject();
				
			} catch (Exception e) {
				  System.out.println("Falha ao receber certificado");
				  throw new  CertificateException (e);
			}
	    	
	    	
	        System.out.println("Enviando certificado");
	             
	        final Certificate cert = CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(certificadoRecebido));
	        rsa.setPublicKey(cert.getPublicKey());
	    }

	    private void chaves() throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, NoSuchAlgorithmException {
	        final char[] chaveSimetrica;
	        final char[] chavePublica = new String(rsa.getPublicKey().getEncoded()).toCharArray();
	        final Key chave = ChaveDerivada(chavePublica);
	        aes.setKey(chave);
	        chaveSimetrica = Hex.encodeHex(aes.encrypt(chave.getEncoded()));
	        enviarChaveSimetrica(chaveSimetrica);
	    }
}
