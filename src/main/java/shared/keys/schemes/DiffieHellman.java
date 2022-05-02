package shared.keys.schemes;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;

public class DiffieHellman {

    private static final BigInteger G = BigInteger.valueOf(3);
    private static final BigInteger N = BigInteger.valueOf(123456789);

    public static BigInteger generatePrivateKey(Integer bits) {
        Random randomGenerator = null;
        try {
            randomGenerator = SecureRandom.getInstance("SHA1PRNG");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return new BigInteger(bits, randomGenerator);
    }

    public static BigInteger generatePublicKey(BigInteger privateKey) {
        return G.modPow(privateKey, N);
    }

    public static BigInteger computePrivateKey(BigInteger publicKey, BigInteger privateKey) {
        return publicKey.modPow(privateKey, N);
    }

}