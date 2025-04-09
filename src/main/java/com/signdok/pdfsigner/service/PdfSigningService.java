package com.signdok.pdfsigner.service;

import com.itextpdf.io.image.ImageDataFactory;
import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.signatures.*;
import com.itextpdf.io.image.ImageData;
import com.signdok.pdfsigner.model.SigningRequest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.imageio.ImageIO;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.text.SimpleDateFormat;
import java.util.Date;
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

        ImageData signatureGraphic = createDefaultSignatureGraphic(request.getCommonName());

//        // Configure signature appearance
//        Rectangle rect = new Rectangle(36, 648, 200, 100);
//        PdfSignatureAppearance appearance = signer.getSignatureAppearance()
//                .setReason(request.getReason())
//                .setLocation(request.getLocation())
//                .setContact(request.getContact())
//                .setReuseAppearance(false)
//                .setPageRect(rect)
//                .setPageNumber(1)
//                .setSignatureGraphic(signatureGraphic)
//                .setLayer2Text("Signed by: " + request.getCommonName() + "\nReason: " + request.getReason() +
//                        "\nLocation: " + request.getLocation() + "\nDate: " + new SimpleDateFormat("yyyy.MM.dd HH:mm:ss z").format(new Date()))
//                .setRenderingMode(PdfSignatureAppearance.RenderingMode.GRAPHIC_AND_DESCRIPTION);

        // Configure signing
        signer.setFieldName("Signature1");

        // Create signing instance
        IExternalSignature pks = new PrivateKeySignature(privateKey, DigestAlgorithms.SHA256, BouncyCastleProvider.PROVIDER_NAME);
        IExternalDigest digest = new BouncyCastleDigest();

        // Sign the document
        signer.signDetached(digest, pks, chain, null, null, null, 0, PdfSigner.CryptoStandard.CMS);
    }

    private ImageData createDefaultSignatureGraphic(String name) throws Exception {
        int width = 200;
        int height = 100;
        BufferedImage image = new BufferedImage(width, height, BufferedImage.TYPE_INT_ARGB);
        Graphics2D g2d = image.createGraphics();

        // Enable antialiasing
        g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g2d.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);

        // Set background (transparent)
        g2d.setBackground(new java.awt.Color(0, 0, 0, 0));
        g2d.clearRect(0, 0, width, height);

        // Draw border
        g2d.setColor(new java.awt.Color(0, 0, 139)); // Dark blue
        g2d.setStroke(new BasicStroke(2));
        g2d.drawRect(1, 1, width - 2, height - 2);

        // Draw signature text
        g2d.setColor(new java.awt.Color(0, 0, 139));
        g2d.setFont(new Font("Arial", Font.BOLD, 20));
        String text = "Digitally signed by:";
        int textX = (width - g2d.getFontMetrics().stringWidth(text)) / 2;
        g2d.drawString(text, textX, 30);

        // Draw name
        g2d.setFont(new Font("Arial", Font.PLAIN, 16));
        int nameX = (width - g2d.getFontMetrics().stringWidth(name)) / 2;
        g2d.drawString(name, nameX, 60);

        g2d.dispose();

        // Convert BufferedImage to bytes
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ImageIO.write(image, "PNG", baos);
        byte[] imageBytes = baos.toByteArray();

        return ImageDataFactory.create(imageBytes);
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
