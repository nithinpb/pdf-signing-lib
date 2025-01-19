package com.signdok.pdfsigner.model;

public class SigningRequest {
    private final String input;
    private final String output;
    private final String keystorePath;
    private final String keystorePassword;
    private final String keyAlias;
    private final String commonName;
    private final String organization;
    private final String country;
    private final String reason;
    private final String location;
    private final String contact;

    private SigningRequest(Builder builder) {
        this.input = builder.input;
        this.output = builder.output;
        this.keystorePath = builder.keystorePath;
        this.keystorePassword = builder.keystorePassword;
        this.keyAlias = builder.keyAlias;
        this.commonName = builder.commonName;
        this.organization = builder.organization;
        this.country = builder.country;
        this.reason = builder.reason;
        this.location = builder.location;
        this.contact = builder.contact;
    }

    public String getInput() {
        return input;
    }

    public String getOutput() {
        return output;
    }

    public String getKeystorePath() {
        return keystorePath;
    }

    public String getKeystorePassword() {
        return keystorePassword;
    }

    public String getKeyAlias() {
        return keyAlias;
    }

    public String getCommonName() {
        return commonName;
    }

    public String getOrganization() {
        return organization;
    }

    public String getCountry() {
        return country;
    }

    public String getReason() {
        return reason;
    }

    public String getLocation() {
        return location;
    }

    public String getContact() {
        return contact;
    }

    public static class Builder {
        private String input;
        private String output;
        private String keystorePath;
        private String keystorePassword;
        private String keyAlias;
        private String commonName;
        private String organization;
        private String country;
        private String privateKey;
        private String reason;
        private String location;
        private String contact;

        public Builder input(String input) {
            this.input = input;
            return this;
        }

        public Builder output(String output) {
            this.output = output;
            return this;
        }

        public Builder keystorePath(String keystorePath) {
            this.keystorePath = keystorePath;
            return this;
        }

        public Builder keystorePassword(String keystorePassword) {
            this.keystorePassword = keystorePassword;
            return this;
        }

        public Builder keyAlias(String keyAlias) {
            this.keyAlias = keyAlias;
            return this;
        }

        public Builder commonName(String commonName) {
            this.commonName = commonName;
            return this;
        }

        public Builder organization(String organization) {
            this.organization = organization;
            return this;
        }

        public Builder country(String country) {
            this.country = country;
            return this;
        }

        public Builder reason(String reason) {
            this.reason = reason;
            return this;
        }

        public Builder location(String location) {
            this.location = location;
            return this;
        }

        public Builder contact(String contact) {
            this.contact = contact;
            return this;
        }

        public SigningRequest build() {
            return new SigningRequest(this);
        }
    }
}
