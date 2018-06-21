import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class CertificateUtils {

	private static final long ONE_YEAR = 1000L * 60 * 60 * 24 * 365;
	private static final String AUTORIDADE_CERTIFICADORA_MARCOS = "CN=Marcos emissor AC";

	private static X509Certificate CertificadoV1(final PrivateKey caSignerKey, final PublicKey caPublicKey)
		throws GeneralSecurityException, IOException, OperatorCreationException {
		final X509v1CertificateBuilder builderCertificadov1 = new JcaX509v1CertificateBuilder(
			new X500Name(AUTORIDADE_CERTIFICADORA_MARCOS),
			BigInteger.valueOf(System.currentTimeMillis()),
			new Date(System.currentTimeMillis() - 1000L * 5),
			new Date(System.currentTimeMillis() + ONE_YEAR),
			new X500Name(AUTORIDADE_CERTIFICADORA_MARCOS),
			caPublicKey);

		final JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA384withRSA").setProvider("BCFIPS");
		return new JcaX509CertificateConverter().setProvider("BCFIPS").getCertificate(builderCertificadov1.build(signerBuilder.build(caSignerKey)));
	}

	private static X509Certificate CertificadoV3(final X509Certificate certificadoAC, final PrivateKey chavePrivadaAC, final PublicKey chavePublica, final String commonName)
		throws GeneralSecurityException, CertIOException, OperatorCreationException {
		final X509v3CertificateBuilder builderCertificadov3 = new JcaX509v3CertificateBuilder(
			certificadoAC.getSubjectX500Principal(),
			BigInteger.valueOf(System.currentTimeMillis()).multiply(BigInteger.valueOf(100)),
			new Date(System.currentTimeMillis() - 1000L * 5),
			new Date(System.currentTimeMillis() + ONE_YEAR),
			new X500Principal("CN=" + commonName), chavePublica);

		final JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
		builderCertificadov3.addExtension(Extension.subjectKeyIdentifier, Boolean.FALSE, extUtils.createSubjectKeyIdentifier(chavePublica));
		builderCertificadov3.addExtension(Extension.authorityKeyIdentifier, Boolean.FALSE, extUtils.createAuthorityKeyIdentifier(certificadoAC.getPublicKey()));
		builderCertificadov3.addExtension(Extension.basicConstraints, Boolean.TRUE, new BasicConstraints(Boolean.FALSE));

		final JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA256WithRSAEncryption").setProvider("BCFIPS");
		return new JcaX509CertificateConverter().setProvider("BCFIPS").getCertificate(builderCertificadov3.build(signerBuilder.build(chavePrivadaAC)));
	}

    /**
     *
     * @param chavePrivadaAC = chave privada da AC
     * @param chavePublicaAC = chave publica da AC
     * @param chavePublica = chave publica
     * @return retorna um certificado x509V3 assinado
     * @throws OperatorCreationException
     * @throws GeneralSecurityException
     * @throws IOException
     */
    public static X509Certificate CertificadoAssinado(final PublicKey chavePublica, final PrivateKey chavePrivadaAC, final PublicKey chavePublicaAC, final String commonName)
		throws OperatorCreationException, GeneralSecurityException, IOException {
		final X509Certificate certificadoAC = CertificadoV1(chavePrivadaAC, chavePublicaAC);
		return CertificadoV3(certificadoAC, chavePrivadaAC, chavePublica, commonName);
	}
}
