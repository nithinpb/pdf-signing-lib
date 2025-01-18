package com.signdok.pdfsigner;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.Options;

/**
 * Hello world!
 */
public class Main {
    public static void main(String[] args) {
        Options options = new Options();
        options.addOption("i", "input", true, "Input PDF path");
        options.addOption("o", "output", true, "Output PDF path");
        options.addOption("c", "cert", true, "Certificate path");
        options.addOption("k", "key", true, "Private key path");

        CommandLineParser parser = new DefaultParser();
        try {
            CommandLine cmd = parser.parse(options, args);
            System.out.println("Input: " + cmd.getOptionValue("i"));
            System.out.println("Output: " + cmd.getOptionValue("o"));
            System.out.println("Certificate: " + cmd.getOptionValue("c"));
            System.out.println("Key: " + cmd.getOptionValue("k"));
            System.out.println("Other Arguments: " + cmd.getArgList());
        } catch (Exception e) {
            System.err.println(e.getMessage());
            System.exit(1);
        }
    }
}
