package shared.keys.schemes;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class SymmetricEncryptionScheme {
    public static SecretKey generateKey(String algorithm, Integer keySize) throws NoSuchAlgorithmException {
        SecureRandom secureRandom = new SecureRandom();
        KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm);
        keyGenerator.init(keySize, secureRandom);
        return keyGenerator.generateKey();
    }
}
