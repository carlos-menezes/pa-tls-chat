package server.client;

import shared.encryption.validator.EncryptionAlgorithmType;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PublicKey;

/**
 * The <code>ClientSpec</code> class represents all the characteristics that a client will
 * have that are relevant to the server.
 * These characteristics are the socket connection, encryption algorithm used by the client,
 * key size for the encryption and the hashing algorithm used.
 */
public class ClientSpec {

    private Socket socket;
    private String encryptionAlgorithm;
    private Integer keySize;
    private String hashingAlgorithm;
    private EncryptionAlgorithmType encryptionAlgorithmType;
    private PublicKey publicSigningKey;
    private PublicKey publicRSAKey;

    // Key used to derive the SecretKeySpec for symmetric encryption
    private BigInteger symmetricEncryptionKey;

    // Keys used to communicate with the client when asymmetric encryption is used
    private KeyPair serverRSAKeys;
    private KeyPair serverSigningKeys;

    private ObjectInputStream objectInputStream;
    private ObjectOutputStream objectOutputStream;

    public Socket getSocket() {
        return this.socket;
    }

    public String getEncryptionAlgorithm() {
        return this.encryptionAlgorithm;
    }

    public Integer getKeySize() {
        return this.keySize;
    }

    public String getHashingAlgorithm() {
        return this.hashingAlgorithm;
    }

    public EncryptionAlgorithmType getEncryptionAlgorithmType() {
        return this.encryptionAlgorithmType;
    }

    public PublicKey getPublicSigningKey() {
        return publicSigningKey;
    }

    public PublicKey getPublicRSAKey() {
        return publicRSAKey;
    }

    public BigInteger getSymmetricEncryptionKey() {
        return symmetricEncryptionKey;
    }

    public ObjectInputStream getObjectInputStream() {
        return this.objectInputStream;
    }

    public ObjectOutputStream getObjectOutputStream() {
        return this.objectOutputStream;
    }

    public KeyPair getServerRSAKeys() {
        return serverRSAKeys;
    }

    public KeyPair getServerSigningKeys() {
        return serverSigningKeys;
    }

    public ClientSpec setServerRSAKeys(KeyPair serverRSAKeys) {
        this.serverRSAKeys = serverRSAKeys;
        return this;
    }

    public static final class Builder {
        private Socket socket;
        private String encryptionAlgorithm;
        private Integer keySize;
        private String hashingAlgorithm;
        private EncryptionAlgorithmType encryptionAlgorithmType;
        private PublicKey publicSigningKey;
        private PublicKey publicRSAKey;

        // Key used to derive the SecretKeySpec for symmetric encryption
        private BigInteger symmetricEncryptionKey;

        // Keys used to communicate with the client when asymmetric encryption is used
        private KeyPair serverRSAKeys;
        private KeyPair serverSigningKeys;

        private ObjectInputStream objectInputStream;
        private ObjectOutputStream objectOutputStream;

        public Builder() {
        }

        public Builder withSocket(Socket socket) {
            this.socket = socket;
            return this;
        }

        public Builder withEncryptionAlgorithm(String encryptionAlgorithm) {
            this.encryptionAlgorithm = encryptionAlgorithm;
            return this;
        }

        public Builder withKeySize(Integer keySize) {
            this.keySize = keySize;
            return this;
        }

        public Builder withHashingAlgorithm(String hashingAlgorithm) {
            this.hashingAlgorithm = hashingAlgorithm;
            return this;
        }

        public Builder withEncryptionAlgorithmType(EncryptionAlgorithmType encryptionAlgorithmType) {
            this.encryptionAlgorithmType = encryptionAlgorithmType;
            return this;
        }

        public Builder withPublicSigningKey(PublicKey publicSigningKey) {
            this.publicSigningKey = publicSigningKey;
            return this;
        }

        public Builder withPublicRSAKey(PublicKey publicRSAKey) {
            this.publicRSAKey = publicRSAKey;
            return this;
        }

        public Builder withSymmetricEncryptionKey(BigInteger symmetricEncryptionKey) {
            this.symmetricEncryptionKey = symmetricEncryptionKey;
            return this;
        }

        public Builder withObjectOutputStream(ObjectOutputStream objectOutputStream) {
            this.objectOutputStream = objectOutputStream;
            return this;
        }

        public Builder withObjectInputStream(ObjectInputStream objectInputStream) {
            this.objectInputStream = objectInputStream;
            return this;
        }

        public Builder withServerRSAKeys(KeyPair keyPair) {
            this.serverRSAKeys = keyPair;
            return this;
        }

        public Builder withServerSigningKeys(KeyPair keyPair) {
            this.serverSigningKeys = keyPair;
            return this;
        }

        public ClientSpec build() {
            ClientSpec clientSpec = new ClientSpec();
            clientSpec.encryptionAlgorithmType = encryptionAlgorithmType;
            clientSpec.keySize = this.keySize;
            clientSpec.hashingAlgorithm = this.hashingAlgorithm;
            clientSpec.symmetricEncryptionKey = this.symmetricEncryptionKey;
            clientSpec.publicSigningKey = this.publicSigningKey;
            clientSpec.publicRSAKey = this.publicRSAKey;
            clientSpec.encryptionAlgorithm = this.encryptionAlgorithm;
            clientSpec.socket = this.socket;
            clientSpec.objectInputStream = this.objectInputStream;
            clientSpec.objectOutputStream = this.objectOutputStream;
            clientSpec.serverSigningKeys = this.serverSigningKeys;
            clientSpec.serverRSAKeys = this.serverRSAKeys;
            return clientSpec;
        }
    }
}