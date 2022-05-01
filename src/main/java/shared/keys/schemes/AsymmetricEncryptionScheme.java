package shared.keys.schemes;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class AsymmetricEncryptionScheme {
    public static KeyPair generateKeys(String algorithm, Integer keySize) throws NoSuchAlgorithmException {
        SecureRandom secureRandom = new SecureRandom();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
        keyPairGenerator.initialize(keySize, secureRandom);
        return keyPairGenerator.generateKeyPair();
    }
}
