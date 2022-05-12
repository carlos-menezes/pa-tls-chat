package shared.message.communication;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.*;
import server.client.ClientSpec;
import shared.encryption.codec.Enconder;
import shared.encryption.validator.EncryptionAlgorithmType;
import shared.keys.schemes.AsymmetricEncryptionScheme;
import shared.keys.schemes.DiffieHellman;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.math.BigInteger;
import java.net.Socket;
import java.security.*;

public class ServerMessageTest {

    private final String sender = "JohnDoe";
    private final String message = "Hello World";
    private final Socket socket = new Socket();
    private final BigInteger privateSharedDHKey = DiffieHellman.generatePrivateKey();
    private ClientSpec clientSpec;

    @BeforeEach
    void setUp() throws NoSuchAlgorithmException {
        KeyPair clientSigningKeys = AsymmetricEncryptionScheme.generateKeys(4096);
        KeyPair serverSigningKeys = AsymmetricEncryptionScheme.generateKeys(4096);
        this.clientSpec = new ClientSpec.Builder()
                .withSocket(socket)
                .withEncryptionAlgorithmType(EncryptionAlgorithmType.SYMMETRIC)
                .withEncryptionAlgorithm("AES")
                .withKeySize(256)
                .withHashingAlgorithm("MD5")
                .withSymmetricEncryptionKey(privateSharedDHKey)
                .withPublicSigningKey(clientSigningKeys.getPublic())
                .withServerSigningKeys(serverSigningKeys)
                .build();
    }

    @Test
    @DisplayName("Should be able to extract the message")
    void testGetMessage() throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException,
            BadPaddingException, SignatureException, InvalidKeyException {
        ServerMessage serverMessage = new ServerMessage(this.sender, this.message, clientSpec);
        byte[] message = serverMessage.getMessage();
        byte[] expected = Enconder.encodeMessage(this.message, this.clientSpec);
        assertArrayEquals(message, expected);
    }

    @Test
    @DisplayName("Should be able to get the sender")
    void TestGetSender() throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException,
            BadPaddingException, SignatureException, InvalidKeyException {
        ServerMessage serverMessage = new ServerMessage(this.sender, this.message, clientSpec);
        assertEquals(serverMessage.getSender(), this.sender);
    }

    @Test
    @DisplayName("Should be able to get the signature value")
    void testGetSignature() throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException,
            BadPaddingException, SignatureException, InvalidKeyException {
        ServerMessage serverMessage = new ServerMessage(this.sender, this.message, clientSpec);
        byte[] expected = Enconder.createSignature(this.message, this.clientSpec.getHashingAlgorithm(), this.clientSpec.getServerSigningKeys().getPrivate());
        assertArrayEquals(serverMessage.getSignature(), expected);
    }
}
