package com.signdok.pdfsigner;

import com.signdok.pdfsigner.model.SigningRequest;
import com.signdok.pdfsigner.service.PdfSigningService;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.Options;

import static java.lang.System.exit;

public class Main {
    public static void main(String[] args) {
        Options options = getOptions();
        CommandLineParser parser = new DefaultParser();
        try {
            CommandLine cmd = parser.parse(options, args);
            SigningRequest request = getSigningRequest(cmd);
            PdfSigningService service = new PdfSigningService();
            service.signPdf(request);

            if (service.verifySignature(request.getOutput())) {
                System.out.println("Document signed and verified successfully");
            } else {
                System.err.println("Signature verification failed");
                exit(1);
            }

            if (cmd.hasOption("y")) {
                service.exportPublicCertificate(
                        request.getKeystorePath(),
                        request.getKeystorePassword(),
                        request.getKeyAlias(),
                        cmd.getOptionValue("y")
                );
            }
        } catch (Exception e) {
            System.err.println(e.getMessage());
            exit(1);
        }
    }

    private static SigningRequest getSigningRequest(CommandLine cmd) {
        return new SigningRequest.Builder()
                .input(cmd.getOptionValue("i"))
                .output(cmd.getOptionValue("o"))
                .keystorePath(cmd.getOptionValue("k"))
                .keystorePassword(cmd.getOptionValue("p"))
                .keyAlias(cmd.getOptionValue("a"))
                .commonName(cmd.getOptionValue("n"))
                .organization(cmd.getOptionValue("g"))
                .country(cmd.getOptionValue("c"))
                .reason(cmd.getOptionValue("r"))
                .location(cmd.getOptionValue("l"))
                .contact(cmd.getOptionValue("n"))
                .build();
    }

    private static Options getOptions() {
        Options options = new Options();
        options.addOption("i", "input", true, "Input PDF path");
        options.addOption("o", "output", true, "Output PDF path");
        options.addOption("k", "keystorePath", true, "Keystore path");
        options.addOption("p", "keystorePassword", true, "Keystore password");
        options.addOption("a", "keystoreAlias", true, "Keystore alias");
        options.addOption("n", "keystoreCommonName", true, "Keystore common name");
        options.addOption("g", "keystoreOrg", true, "Keystore org");
        options.addOption("c", "keystoreCountry", true, "Keystore country");
        options.addOption("r", "reason", true, "Reason");
        options.addOption("l", "location", true, "Location");
        options.addOption("n", "contact", true, "Contact");
        options.addOption("y", "generate-public-key", true, "Generate public key");
        return options;
    }
}
