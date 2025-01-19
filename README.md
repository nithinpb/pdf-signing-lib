# PDF Signing Lib

This is a simple library to sign PDF files using a certificate.

## Run
```
mvn clean package assembly:single #Creates a jar with all dependencies
java -jar target/pdf-signing-lib-1.0-SNAPSHOT-jar-with-dependencies.jar -i input_file -o output_file
```

## Specific Run
This generates the signed PDF file with the given input file and output file. The keystore file is required to sign the PDF file. The keystore file should be a p12 file. The password is the password for the keystore file. The alias is the alias of the certificate in the keystore file. The name is the name of the signer. The organization is the organization of the signer. The country is the country of the signer. The reason is the reason for signing the document. The location is the location of the signer. The email is the email of the signer
```
java -jar pdf-signing-lib/target/pdf-signing-lib-1.0-SNAPSHOT-jar-with-dependencies.jar -i pdf-signing-lib/sample/3pages.pdf -o signed3pages.pdf -k ./keystore.p12 -p password -a sindok -n Signdok -g "Beskar LLP" -c "IN" -r "Testing" -l "Bangalore" -n "admin@signdok.com" -y "/Users/nithinbetegeri/Coding/beskar"
```