package shared.encryption.algorithms;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;

/**
 * The <code>DiffieHellman</code> class represents all the methods needed to exchange keys
 * using the Diffie-Hellman method.
 */
public class DiffieHellman {

    private static final BigInteger G = BigInteger.valueOf( 3 );
    private static final BigInteger N = BigInteger.valueOf( 1289971646 );
    private static final int NUM_BITS = 128;

    // Maybe pass the number of bits as an argument

    /**
     * Method that generates a private key according to the Diffie-Hellman method.
     *
     * @return Generated private key
     * @throws NoSuchAlgorithmException Exception thrown when the hash algorithm does not exist
     */
    public static BigInteger generatePrivateKey () throws NoSuchAlgorithmException {
        Random randomGenerator = SecureRandom.getInstance("SHA1PRNG");
        return new BigInteger(NUM_BITS , randomGenerator);
    }

    /**
     * Method that generates a public key based on the client private key
     * according to the Diffie-Hellman method.
     *
     * @param privateKey Client private key
     * @return Generated public key
     */
    public static BigInteger generatePublicKey (BigInteger privateKey) {
        return G.modPow(privateKey , N);
    }

    /**
     * Method that computes the private key given a public and private key
     * according to the Diffie-Hellman method.
     *
     * @param publicKey Other client public key
     * @param privateKey Client private Key
     * @return Computed private key
     */
    public static BigInteger computePrivateKey (BigInteger publicKey , BigInteger privateKey) {
        return publicKey.modPow(privateKey , N);
    }
}
