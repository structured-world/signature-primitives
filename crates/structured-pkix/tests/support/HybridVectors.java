// Independent interoperability vectors, generated and verified by Bouncy Castle.
// Test keys are ephemeral. Only public DER and captured signed inputs are saved.
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Date;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.*;
import org.bouncycastle.pkcs.*;

public class HybridVectors {
    static class Capture implements ContentSigner {
        final ContentSigner signer;
        final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        Capture(String algorithm, KeyPair key) throws Exception {
            signer = new JcaContentSignerBuilder(algorithm).setProvider("BC").build(key.getPrivate());
        }
        public AlgorithmIdentifier getAlgorithmIdentifier() { return signer.getAlgorithmIdentifier(); }
        public OutputStream getOutputStream() {
            return new OutputStream() {
                public void write(int b) throws java.io.IOException {
                    bytes.write(b); signer.getOutputStream().write(b);
                }
                public void write(byte[] b,int off,int len) throws java.io.IOException {
                    bytes.write(b,off,len); signer.getOutputStream().write(b,off,len);
                }
                public void close() throws java.io.IOException { signer.getOutputStream().close(); }
            };
        }
        public byte[] getSignature() { return signer.getSignature(); }
    }
    static KeyPair ec() throws Exception {
        var generator = KeyPairGenerator.getInstance("EC","BC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }
    static ContentSigner nativeSigner(KeyPair key) throws Exception {
        return new JcaContentSignerBuilder("SHA256withECDSA").setProvider("BC").build(key.getPrivate());
    }
    static SubjectPublicKeyInfo spki(KeyPair key) {
        return SubjectPublicKeyInfo.getInstance(key.getPublic().getEncoded());
    }
    static final X500Name ROOT = new X500Name("CN=Hybrid Test Root");
    static final X500Name LEAF = new X500Name("CN=Hybrid Test Subject");
    static final Date BEFORE = Date.from(Instant.parse("2026-01-01T00:00:00Z"));
    static final Date AFTER = Date.from(Instant.parse("2030-01-01T00:00:00Z"));
    static void save(Path directory,String file,byte[] value) throws Exception { Files.write(directory.resolve(file),value); }
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        Path directory = Path.of(args[0]);
        Files.createDirectories(directory);
        KeyPair root = ec(), leaf = ec();
        KeyPair rootPQ = KeyPairGenerator.getInstance("ML-DSA-65","BC").generateKeyPair();
        KeyPair leafPQ = KeyPairGenerator.getInstance("ML-DSA-65","BC").generateKeyPair();
        var verifier = new JcaContentVerifierProviderBuilder().setProvider("BC");
        var rootBuilder = new X509v3CertificateBuilder(ROOT,BigInteger.ONE,BEFORE,AFTER,ROOT,spki(root));
        rootBuilder.addExtension(Extension.basicConstraints,true,new BasicConstraints(2));
        rootBuilder.addExtension(Extension.keyUsage,true,new KeyUsage(KeyUsage.keyCertSign|KeyUsage.cRLSign));
        rootBuilder.addExtension(Extension.subjectAltPublicKeyInfo,false,spki(rootPQ));
        Capture rootAlternative = new Capture("ML-DSA-65",rootPQ);
        var rootCert = rootBuilder.build(nativeSigner(root),false,rootAlternative);
        var builder = new X509v3CertificateBuilder(ROOT,BigInteger.TWO,BEFORE,AFTER,LEAF,spki(leaf));
        builder.addExtension(Extension.subjectAltPublicKeyInfo,true,spki(leafPQ));
        Capture alternative = new Capture("ML-DSA-65",rootPQ);
        var cert = builder.build(nativeSigner(root),true,alternative);
        if (!cert.isSignatureValid(verifier.build(root.getPublic())) || !cert.isAlternativeSignatureValid(verifier.build(rootPQ.getPublic())))
            throw new IllegalStateException("certificate signatures");
        save(directory,"root.der",rootCert.getEncoded());
        save(directory,"certificate.der",cert.getEncoded());
        save(directory,"certificate-preimage.der",alternative.bytes.toByteArray());
        var crlBuilder = new X509v2CRLBuilder(ROOT,BEFORE);
        crlBuilder.setNextUpdate(AFTER);
        Capture crlAlternative = new Capture("ML-DSA-65",rootPQ);
        var crl = crlBuilder.build(nativeSigner(root),false,crlAlternative);
        if (!crl.isSignatureValid(verifier.build(root.getPublic())) || !crl.isAlternativeSignatureValid(verifier.build(rootPQ.getPublic())))
            throw new IllegalStateException("CRL signatures");
        save(directory,"crl.der",crl.getEncoded());
        save(directory,"crl-preimage.der",crlAlternative.bytes.toByteArray());
        var requestBuilder = new PKCS10CertificationRequestBuilder(LEAF,spki(leaf));
        Capture requestAlternative = new Capture("ML-DSA-65",leafPQ);
        var request = requestBuilder.build(nativeSigner(leaf),spki(leafPQ),requestAlternative);
        if (!request.isSignatureValid(verifier.build(leaf.getPublic())) || !request.isAltSignatureValid(verifier.build(leafPQ.getPublic())))
            throw new IllegalStateException("request signatures");
        save(directory,"request.der",request.getEncoded());
        save(directory,"request-preimage.der",requestAlternative.bytes.toByteArray());
        System.out.println("PASS: native and alternative certificate, request and CRL signatures");
    }
}
