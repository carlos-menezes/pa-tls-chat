package shared.encryption.validator.exceptions;

public class InvalidEncryptionAlgorithmException extends RuntimeException {
    public InvalidEncryptionAlgorithmException(String algorithm) {
        super(String.format("Invalid algorithm (%s) provided", algorithm));
    }
}
