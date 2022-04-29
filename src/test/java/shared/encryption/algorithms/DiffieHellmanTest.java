package shared.encryption.algorithms;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.*;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;

class DiffieHellmanTest {

    @Test
    @DisplayName("Should be able to generate a private key")
    void testGeneratePrivateKey() throws NoSuchAlgorithmException{
        assertAll(
            () -> assertDoesNotThrow(() -> {
                BigInteger pk = DiffieHellman.generatePrivateKey();
            }),
            () -> assertTrue(DiffieHellman.generatePrivateKey().bitLength() <= 128)
        );
    }

    @Test
    @DisplayName("Should be able do generate a public key")
    void testGeneratePublicKey() throws NoSuchAlgorithmException {
        BigInteger privateKey = DiffieHellman.generatePrivateKey();
        assertDoesNotThrow(() -> {
            BigInteger pk = DiffieHellman.generatePublicKey(privateKey);
        });
    }

    @Test
    @DisplayName("Should be able to compute private key")
    void testComputePrivateKey() throws NoSuchAlgorithmException {
        BigInteger privateKey = DiffieHellman.generatePrivateKey();
        BigInteger publicKey = DiffieHellman.generatePublicKey(privateKey);
        assertDoesNotThrow(() -> {
            BigInteger pk = DiffieHellman.computePrivateKey(publicKey, privateKey);
        });
    }
}
