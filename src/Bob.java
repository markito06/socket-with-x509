import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.fips.FipsDRBG;
import org.bouncycastle.crypto.util.BasicEntropySourceProvider;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.operator.OperatorCreationException;



public class Bob {

	  static {
	        Security.addProvider(new BouncyCastleFipsProvider());
	        CryptoServicesRegistrar.setSecureRandom(FipsDRBG.SHA512_HMAC.fromEntropySource(new BasicEntropySourceProvider(new SecureRandom(), true)).build(null, false));
	    }

	    public static void startServer(String ipServer, String porta) throws IOException, DecoderException, OperatorCreationException, GeneralSecurityException {
	        final Bob servidor = new Bob(Integer.valueOf(porta), ipServer);
	        servidor.ouvir();
	        servidor.desligar();
	    }
	    private final GerenciadorCertificados gerenciadorCertificados;

	    private final CifradorAES aes;
	    private final CifradorRSA rsa;

	    private final ServerSocket servidor;

	    private X509Certificate certificado;

	    private Socket cliente;
	    private PrintStream out;
	    private Scanner in;
	    private String HOME_FOLDER;
	    private String FILE_NAME;

	    private Bob(final int porta,  final String ipServer) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IOException, OperatorCreationException, GeneralSecurityException {

	    	this.config();
	        final SecureRandom random = new FixedRandom();

	        aes = new CifradorAES(random);
	        rsa = new CifradorRSA(random);

	        ReaderWithInfo ler = new ReaderWithInfo(new InputStreamReader(System.in));

	        gerenciadorCertificados = new GerenciadorCertificados(
	                new File(HOME_FOLDER + File.separator + FILE_NAME), ler.readLine("Digite senha CA: "), ler.readLine("Digite sua senha: "));

	        PublicKey chavePublica = null;
	        PrivateKey chavePrivada = null;

	        certificado = gerenciadorCertificados.getCertificate();
	        chavePrivada = gerenciadorCertificados.getPrivateKey();

	        if (certificado == null || chavePrivada == null) {
	            System.out.println("Arquivo de certificado não criado");
	            System.out.println("Gerando um novo certificado");

	            final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BCFIPS");

	            final KeyPair parDeChavesAC = keyPairGenerator.generateKeyPair();
	            final KeyPair parDeChaves = keyPairGenerator.generateKeyPair();

	            certificado = UtilitariosCertificado.CertificadoAssinado(parDeChaves.getPublic(), parDeChavesAC.getPrivate(), parDeChavesAC.getPublic());

	            chavePublica = certificado.getPublicKey();
	            chavePrivada = parDeChaves.getPrivate();

	            gerenciadorCertificados.setCertificate(certificado);
	            gerenciadorCertificados.setPrivateKey(chavePrivada, certificado);
	        }

	        chavePublica = certificado.getPublicKey();
	        rsa.setPublicKey(chavePublica);
	        rsa.setPrivateKey(chavePrivada);

	        InetAddress addr = InetAddress.getByName(ipServer);
	        final int defaultMaxConnections = 50;
	        servidor = new ServerSocket(porta,defaultMaxConnections, addr);

	    }

	    private void config() {
	    	HOME_FOLDER = System.getProperty("user.home");
	    	FILE_NAME = "myCert.jks";
		}

		private void ouvir() throws IOException, DecoderException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException,
	            KeyStoreException, NoSuchAlgorithmException, CertificateException {

	        System.out.println("Aguardando conexao");
	        cliente = servidor.accept();
	        System.out.println("Cliente conectado");

	        in = new Scanner(cliente.getInputStream());
	        out = new PrintStream(cliente.getOutputStream());

	        /*
	         * Encoding problem solution
	         * */
	        String certificate = new String(certificado.toString().getBytes(), "UTF-8");
	        // final char[] certificate = Hex.encodeHex(certificado.getEncoded());

	        System.out.println("Enviando certificado : ");
	        System.out.println(certificate);
	        out.println(certificado);

	        System.out.println("Recebendo chave simetrica");

	        while (!in.hasNextLine()) {

	            final String recebido = in.nextLine();
	            /*
	             * Para resolver problema de codificação na conversão
	             * @see  org.apache.commons.codec.DecoderException : Odd number of characters
	             * **/
	            final char[] utfCharReceived = new String(recebido.getBytes(), "UTF-8").toCharArray();
	            
	            final String decifrar = new String(aes.decrypt(Hex.decodeHex(utfCharReceived)));

	            System.out.println("\nMensagem Recebida\n");
	            System.out.println("\nTexto Plano\n");
	            System.out.println(decifrar);
	            System.out.println("\nMensagem Codificada\n");
	            System.out.println(recebido);

	            final String mensagem = "Mensagem para o cliente";

	            final char[] enviado = Hex.encodeHex(aes.encrypt(mensagem.getBytes()));

	            System.out.println("\nMensagem Recebida\n");
	            System.out.println("\nTexto Plano\n");
	            System.out.println(mensagem);
	            System.out.println("\nMensagem Codificada\n");
	            System.out.println(String.valueOf(enviado));

	            out.println(Arrays.toString(enviado));

	            System.out.println("Aguardando resposta do cliente");

	        }

	    }

	    private void desligar() throws IOException {

	        servidor.close();

	        try {
	            if (cliente != null) {
	                cliente.close();
	            }
	            if (in != null) {
	                throw new InException();
	            }
	            if (out != null) {
	                throw new OutException();
	            }

	        } catch (InException e) {
	            in.close();
	            System.out.println("Sem entrada");
	        } catch (OutException e) {
	            out.close();
	            System.out.println("Sem saida");
	        }

	    }
}
