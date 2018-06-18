import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class GerenciadorCertificados {

	private final File arquivo;

	private final KeyStore keyStore;
	private final String password;
	private final String passwordChavePrivada;

	public GerenciadorCertificados(final File arquivo, final String password, final String cpPassword)
		throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, NoSuchProviderException {
		
                keyStore = KeyStore.getInstance("JKS");
		
                if(arquivo.exists()) {
			keyStore.load(new FileInputStream(arquivo), password.toCharArray());
		} else {
			keyStore.load(null, null);
			keyStore.store(new FileOutputStream(arquivo), password.toCharArray());
		}
		
                this.arquivo = arquivo;
		this.password = password;
		this.passwordChavePrivada = cpPassword;
	}

	public X509Certificate getCertificate() throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
		return (X509Certificate) keyStore.getCertificate("cert");
	}

	public void setCertificate(final Certificate certificado) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException {
		keyStore.setCertificateEntry("cert", certificado);
		keyStore.store(new FileOutputStream(arquivo), password.toCharArray());
	}

	public PrivateKey getPrivateKey() throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
		return (PrivateKey) keyStore.getKey("pk", passwordChavePrivada.toCharArray());
	}

	public void setPrivateKey(final PrivateKey chavePrivada, final X509Certificate certificado)
		throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException {
		keyStore.setKeyEntry("pk", chavePrivada, passwordChavePrivada.toCharArray(), new X509Certificate[] { certificado });
		keyStore.store(new FileOutputStream(arquivo), password.toCharArray());
	}
}
