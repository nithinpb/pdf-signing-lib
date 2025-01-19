package com.signdok.pdfsigner.service;

import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.signatures.*;
import com.signdok.pdfsigner.model.SigningRequest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.List;

public class PdfSigningService {
    private final CertificateManager certificateManager;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public PdfSigningService() {
        this.certificateManager = new CertificateManager();
    }

    public void signPdf(SigningRequest request) throws Exception {
        // Load or generate certificate if needed
        if (!certificateManager.certificateExists(request.getKeystorePath(), request.getKeystorePassword())) {
            certificateManager.generateSignDocCertificate(
                    request.getKeystorePath(),
                    request.getKeystorePassword(),
                    request.getKeyAlias(),
                    request.getCommonName(),
                    request.getOrganization(),
                    request.getCountry()
            );
        }

        // Load the keystore
        KeyStore keyStore = certificateManager.loadKeyStore(
                request.getKeystorePath(),
                request.getKeystorePassword()
        );
        // Get the private key and certificate chain
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(
                request.getKeyAlias(),
                request.getKeystorePassword().toCharArray()
        );
        Certificate[] chain = keyStore.getCertificateChain(request.getKeyAlias());
        PdfReader reader = new PdfReader(new FileInputStream(request.getInput()));
        PdfSigner signer = new PdfSigner(reader, new FileOutputStream(request.getOutput()), new StampingProperties());

        // Set certification level on the signer
        signer.setCertificationLevel(PdfSigner.CERTIFIED_NO_CHANGES_ALLOWED);

        // Create signing instance
        IExternalSignature pks = new PrivateKeySignature(privateKey, DigestAlgorithms.SHA256, BouncyCastleProvider.PROVIDER_NAME);
        IExternalDigest digest = new BouncyCastleDigest();

        // Sign the document
        signer.signDetached(digest, pks, chain, null, null, null, 0, PdfSigner.CryptoStandard.CMS);
    }

    public boolean verifySignature(String signedPdfPath) throws Exception {
        try (PdfDocument pdfDoc = new PdfDocument(new PdfReader(signedPdfPath))) {
            SignatureUtil signUtil = new SignatureUtil(pdfDoc);
            List<String> names = signUtil.getSignatureNames();

            for (String name : names) {
                PdfPKCS7 pkcs7 = signUtil.readSignatureData(name);
                if (!pkcs7.verifySignatureIntegrityAndAuthenticity()) {
                    return false;
                }
            }
            return !names.isEmpty();
        }
    }

    public File exportPublicCertificate(String keystorePath, String keystorePassword, String keyAlias, String directory) {
        try {
            String outputPath = directory + "/" + keyAlias + ".cer";
            System.out.println("Exporting public certificate to " + outputPath);
            return certificateManager.exportPublicCertificate(keystorePath, keystorePassword, keyAlias, outputPath);
        } catch (Exception e) {
            throw new RuntimeException("Failed to export public certificate", e);
        }
    }
}
