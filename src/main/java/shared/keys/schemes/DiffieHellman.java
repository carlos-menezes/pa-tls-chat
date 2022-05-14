package shared.keys.schemes;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;

/**
 * Implementation of the Diffie-Hellman public key agreement algorithm, as defined in PKCS#3.
 */
public class DiffieHellman {

    private static final BigInteger G = BigInteger.valueOf(3);
    private static final BigInteger N = BigInteger.valueOf(123456789);
    private static final Integer NUM_BITS = 128;

    /**
     * Generates a private key.
     * @return private key
     */
    public static BigInteger generatePrivateKey() {
        try {
            Random randomGenerator = SecureRandom.getInstance("SHA1PRNG");
            return new BigInteger(NUM_BITS, randomGenerator);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return null;
    }

    /**
     * Generates a public key.
     * @param privateKey private key
     * @return public key
     */
    public static BigInteger generatePublicKey(BigInteger privateKey) {
        return G.modPow(privateKey, N);
    }

    /**
     * Computes a private key.
     * @param publicKey public key
     * @param privateKey private key
     * @return private key
     */
    public static BigInteger computePrivateKey(BigInteger publicKey, BigInteger privateKey) {
        return publicKey.modPow(privateKey, N);
    }

}