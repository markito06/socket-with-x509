import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.fips.FipsDRBG;
import org.bouncycastle.crypto.util.BasicEntropySourceProvider;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;

public abstract class SecurityServer {
	

	static {
        Security.addProvider(new BouncyCastleFipsProvider());
        CryptoServicesRegistrar.setSecureRandom(FipsDRBG.SHA512_HMAC.fromEntropySource(new BasicEntropySourceProvider(new SecureRandom(), true)).build(null, false));
    }
	
	
	protected final CertificateManager certificateManager;
	protected LeitorTerminal lerTerminal;
    protected AesCipher aes;
    protected RsaCipher rsa;
    protected X509Certificate certificate;
    
    public SecurityServer() throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, KeyStoreException, CertificateException, IOException {
    	
    	
		lerTerminal = new LeitorTerminal(new InputStreamReader(System.in));

    	this.instanceCiphers();
    	
    	File certificate = this.loadFile();
    	String certCaPass = getPassCa();
    	String certPass = getPassCert();
    	   	
    	certificateManager = new CertificateManager(certificate, certCaPass, certPass);

	}
    
    private File loadFile() {
    	return new File(this.getHomeFolder() + File.separator + this.getFileName());
	}

	private void instanceCiphers() throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {
    	SecureRandom nonceBob = new FixedRandom();
    	aes = new AesCipher(nonceBob);
    	rsa = new RsaCipher(nonceBob);
		
	}

	public abstract String getHomeFolder();
    public abstract String getFileName();
    public abstract String getCommonName() throws IOException;
    public abstract String getPassCa() throws IOException;
    public abstract String getPassCert() throws IOException;;
    public abstract String fillSecondStep() throws IOException;
    public abstract String getAliceNonce() throws Exception;
    
    
    
}
