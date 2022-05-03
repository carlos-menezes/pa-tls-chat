package shared.message.handshake.server;

import org.junit.jupiter.api.Test;
import shared.keys.schemes.AsymmetricEncryptionScheme;
import shared.keys.schemes.DiffieHellman;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ServerHelloTest {
    @Test
    void TestServerHello() throws NoSuchAlgorithmException {
        BigInteger privateKey = DiffieHellman.generatePrivateKey();
        BigInteger publicKey = DiffieHellman.generatePublicKey(privateKey);
        KeyPair keyPair = AsymmetricEncryptionScheme.generateKeys(1024);
        ServerHello serverHello = new ServerHello.Builder()
                .withPublicDHKey(publicKey)
                .withPublicRSAKey(keyPair.getPublic())
                .build();

        assertEquals(serverHello.getPublicDHKey(), publicKey);
        assertEquals(serverHello.getPublicRSAKey(), keyPair.getPublic());
    }
}