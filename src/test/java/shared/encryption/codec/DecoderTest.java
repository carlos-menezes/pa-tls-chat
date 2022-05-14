package shared.encryption.codec;

import client.Client;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import picocli.CommandLine;
import server.client.ClientSpec;
import shared.encryption.validator.EncryptionAlgorithmType;
import shared.keys.schemes.AsymmetricEncryptionScheme;
import shared.keys.schemes.DiffieHellman;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DecoderTest {
    private final String message = "Hello World";
    private Client symmetricClient;
    private ClientSpec symmetricClientSpec;

    private Client asymmmetricClient;
    private ClientSpec asymmetricClientSpec;

    private KeyPair serverSigningKeys;

    @BeforeEach
    void setUp() throws NoSuchAlgorithmException {
        this.serverSigningKeys = AsymmetricEncryptionScheme.generateKeys(4096);
        KeyPair clientSigningKeys = AsymmetricEncryptionScheme.generateKeys(4096);
        KeyPair clientEncryptionKeys = AsymmetricEncryptionScheme.generateKeys(1024);
        KeyPair serverEncryptionKeys = AsymmetricEncryptionScheme.generateKeys(1024);

        String[] symmetricArgs = "-e AES -k 256 -m SHA256withRSA -n pa-user --host localhost --port 1337".split(" ");
        this.symmetricClient = new Client();
        new CommandLine(this.symmetricClient).parseArgs(symmetricArgs);
        this.symmetricClient.setEncryptionAlgorithmType(EncryptionAlgorithmType.SYMMETRIC);
        this.symmetricClient.setServerSigningKey(serverSigningKeys.getPublic());
        BigInteger symmetricEncryptionKey = DiffieHellman.generatePrivateKey();
        this.symmetricClient.setSymmetricEncryptionKey(symmetricEncryptionKey);
        this.symmetricClient.setSigningKeys(clientSigningKeys);
        this.symmetricClient.setHashingAlgorithm("SHA256withRSA");

        String[] asymmetricArgs = "-e RSA -k 1024 -m SHA256withRSA -n pa-user --host localhost --port 1337".split(" ");
        this.asymmmetricClient = new Client();
        new CommandLine(this.asymmmetricClient).parseArgs(asymmetricArgs);
        this.asymmmetricClient.setEncryptionAlgorithmType(EncryptionAlgorithmType.ASYMMETRIC);
        this.asymmmetricClient.setServerSigningKey(serverSigningKeys.getPublic());
        this.asymmmetricClient.setSigningKeys(clientSigningKeys);
        this.asymmmetricClient.setRSAKeys(clientEncryptionKeys);
        this.asymmmetricClient.setHashingAlgorithm("SHA256withRSA");
        this.asymmmetricClient.setServerRSAKey(serverEncryptionKeys.getPublic());

        this.symmetricClientSpec = new ClientSpec.Builder()
                .withEncryptionAlgorithmType(EncryptionAlgorithmType.SYMMETRIC)
                .withEncryptionAlgorithm("AES")
                .withServerSigningKeys(serverSigningKeys)
                .withPublicSigningKey(clientSigningKeys.getPublic())
                .withHashingAlgorithm("SHA256withRSA")
                .withSymmetricEncryptionKey(this.symmetricClient.getSymmetricEncryptionKey())
                .withKeySize(256)
                .build();

        this.asymmetricClientSpec = new ClientSpec.Builder()
                .withEncryptionAlgorithmType(EncryptionAlgorithmType.ASYMMETRIC)
                .withEncryptionAlgorithm("RSA")
                .withServerSigningKeys(serverSigningKeys)
                .withPublicSigningKey(clientSigningKeys.getPublic())
                .withHashingAlgorithm("SHA256withRSA")
                .withPublicRSAKey(clientEncryptionKeys.getPublic())
                .withKeySize(1024)
                .withServerRSAKeys(serverEncryptionKeys)
                .build();
    }

    @Test
    void testDecodeMessageSymmetric() throws NoSuchPaddingException, IllegalBlockSizeException,
            NoSuchAlgorithmException,
            BadPaddingException, InvalidKeyException {
        byte[] encodedMessage = Encoder.encodeMessage(this.message, this.symmetricClientSpec);
        byte[] decodedContent = Decoder.decodeMessage(encodedMessage, this.symmetricClient);
        assertArrayEquals(decodedContent, this.message.getBytes());

        encodedMessage = Encoder.encodeMessage(this.message, this.symmetricClientSpec);
        decodedContent = Decoder.decodeMessage(encodedMessage, this.symmetricClient);
        assertArrayEquals(decodedContent, this.message.getBytes());
    }

    @Test
    void testDecodeMessageAsymmetric() throws NoSuchPaddingException, IllegalBlockSizeException,
            NoSuchAlgorithmException,
            BadPaddingException, InvalidKeyException {
        byte[] encodedMessage = Encoder.encodeMessage(this.message, this.asymmetricClientSpec);
        byte[] decodedContent = Decoder.decodeMessage(encodedMessage, this.asymmmetricClient);
        assertArrayEquals(decodedContent, this.message.getBytes());

        byte[] encodedMessageB = Encoder.encodeMessage(this.message, this.asymmmetricClient);
        byte[] decodedContentB = Decoder.decodeMessage(encodedMessageB, this.asymmetricClientSpec);
        assertArrayEquals(decodedContentB, this.message.getBytes());
    }


    @Test
    void testValidateSignatureSymmetric() throws NoSuchPaddingException, IllegalBlockSizeException,
            NoSuchAlgorithmException,
            BadPaddingException, InvalidKeyException, SignatureException {

        byte[] encodedMessage = Encoder.encodeMessage(this.message, this.symmetricClientSpec);
        byte[] signature = Encoder.createSignature(message, this.symmetricClientSpec.getHashingAlgorithm(),
                                                   this.symmetricClientSpec.getServerSigningKeys().getPrivate());

        byte[] decodedContent = Decoder.decodeMessage(encodedMessage, this.symmetricClient);
        boolean validateSignature = Decoder.validateSignature(decodedContent, this.symmetricClient.getHashingAlgorithm(),
                                                              this.symmetricClient.getServerSigningKey(), signature);
        assertTrue(validateSignature);

        encodedMessage = Encoder.encodeMessage(this.message, this.symmetricClient);
        signature = Encoder.createSignature(message, this.symmetricClient.getHashingAlgorithm(),
                                                   this.symmetricClient.getSigningKeys().getPrivate());
        decodedContent = Decoder.decodeMessage(encodedMessage, this.symmetricClientSpec);
        validateSignature = Decoder.validateSignature(decodedContent, this.symmetricClientSpec.getHashingAlgorithm(),
                                                      this.symmetricClientSpec.getPublicSigningKey(), signature);
        assertTrue(validateSignature);
    }

    @Test
    void testValidateSignatureAsymmetric() throws NoSuchPaddingException, IllegalBlockSizeException,
            NoSuchAlgorithmException,
            BadPaddingException, InvalidKeyException, SignatureException {

        byte[] encodedMessage = Encoder.encodeMessage(this.message, this.asymmetricClientSpec);
        byte[] signature = Encoder.createSignature(message, this.asymmetricClientSpec.getHashingAlgorithm(),
                                                   this.serverSigningKeys.getPrivate());

        byte[] decodedContent = Decoder.decodeMessage(encodedMessage, this.asymmmetricClient);
        boolean validateSignature = Decoder.validateSignature(decodedContent, this.asymmmetricClient.getHashingAlgorithm(),
                                                              this.asymmmetricClient.getServerSigningKey(), signature);
        assertTrue(validateSignature);
    }


}