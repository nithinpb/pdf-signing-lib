package com.signdok.pdfsigner.service;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;

public class CertificateManager {
    private static final String KEYSTORE_TYPE = "PKCS12";
    private static final String SIGNATURE_ALGORITHM = "SHA256WithRSA";
    private static final String PROVIDER_NAME = BouncyCastleProvider.PROVIDER_NAME;
    private static final int VALIDITY_DAYS = 365;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public File exportPublicCertificate(String keystorePath, String keystorePassword,
                                        String alias, String outputPath) throws Exception {
        KeyStore keyStore = loadKeyStore(keystorePath, keystorePassword);
        X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
        File outputFile = new File(outputPath);

        try (FileOutputStream fos = new FileOutputStream(outputFile)) {
            fos.write(cert.getEncoded());
        }
        System.out.println("Certificate exported to " + outputFile.getAbsolutePath());
        return outputFile;
    }

    public boolean certificateExists(String keystorePath, String password) {
        File keystoreFile = new File(keystorePath);
        if (!keystoreFile.exists()) {
            return false;
        }

        try (FileInputStream fis = new FileInputStream(keystoreFile)) {
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
            keyStore.load(fis, password.toCharArray());
            return keyStore.size() > 0;
        } catch (Exception e) {
            return false;
        }
    }

    public void generateSignDocCertificate(String keystorePath, String password, String alias,
                                           String commonName, String organization, String country)
            throws Exception {
        // Generate key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", PROVIDER_NAME);
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // Create certificate
        X509Certificate cert = generateX509Certificate(keyPair, commonName, organization, country);

        // Store in keystore
        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
        if (new File(keystorePath).exists()) {
            try (FileInputStream fis = new FileInputStream(keystorePath)) {
                keyStore.load(fis, password.toCharArray());
            }
        } else {
            keyStore.load(null, password.toCharArray());
        }

        keyStore.setKeyEntry(alias, keyPair.getPrivate(), password.toCharArray(),
                new X509Certificate[]{cert});

        try (FileOutputStream fos = new FileOutputStream(keystorePath)) {
            keyStore.store(fos, password.toCharArray());
        }
    }

    private X509Certificate generateX509Certificate(KeyPair keyPair, String commonName,
                                                    String organization, String country)
            throws Exception {
        X500Name subject = new X500Name("CN=" + commonName + ", O=" + organization + ", C=" + country);
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = new Date();
        Date notAfter = new Date(System.currentTimeMillis() + VALIDITY_DAYS * 86400000L);

        SubjectPublicKeyInfo pubKeyInfo = SubjectPublicKeyInfo.getInstance(
                keyPair.getPublic().getEncoded());

        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
                subject,     // Issuer and subject are the same for self-signed
                serial,
                notBefore,
                notAfter,
                subject,
                pubKeyInfo
        );

        ContentSigner signer = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM)
                .setProvider(PROVIDER_NAME)
                .build(keyPair.getPrivate());

        return new JcaX509CertificateConverter()
                .setProvider(PROVIDER_NAME)
                .getCertificate(certBuilder.build(signer));
    }

    public KeyStore loadKeyStore(String keystorePath, String password) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
        try (FileInputStream fis = new FileInputStream(keystorePath)) {
            keyStore.load(fis, password.toCharArray());
        }
        return keyStore;
    }
}
