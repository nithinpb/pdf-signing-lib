# PDF Signing Lib

This is a simple library to sign PDF files using a certificate.

## Run
```
mvn clean package assembly:single #Creates a jar with all dependencies
java -jar target/pdf-signing-lib-1.0-SNAPSHOT-jar-with-dependencies.jar -i input_file -o output_file
```
