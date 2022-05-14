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

    /**
     * Gets socket.
     *
     * @return the socket
     */
    public Socket getSocket() {
        return this.socket;
    }

    /**
     * Gets encryption algorithm.
     *
     * @return the encryption algorithm
     */
    public String getEncryptionAlgorithm() {
        return this.encryptionAlgorithm;
    }

    /**
     * Gets key size.
     *
     * @return the key size
     */
    public Integer getKeySize() {
        return this.keySize;
    }

    /**
     * Gets hashing algorithm.
     *
     * @return the hashing algorithm
     */
    public String getHashingAlgorithm() {
        return this.hashingAlgorithm;
    }

    /**
     * Gets encryption algorithm type.
     *
     * @return the encryption algorithm type
     */
    public EncryptionAlgorithmType getEncryptionAlgorithmType() {
        return this.encryptionAlgorithmType;
    }

    /**
     * Gets public signing key.
     *
     * @return the public signing key
     */
    public PublicKey getPublicSigningKey() {
        return this.publicSigningKey;
    }

    /**
     * Gets public rsa key.
     *
     * @return the public rsa key
     */
    public PublicKey getPublicRSAKey() {
        return this.publicRSAKey;
    }

    /**
     * Gets symmetric encryption key.
     *
     * @return the symmetric encryption key
     */
    public BigInteger getSymmetricEncryptionKey() {
        return this.symmetricEncryptionKey;
    }

    /**
     * Gets object input stream.
     *
     * @return the object input stream
     */
    public ObjectInputStream getObjectInputStream() {
        return this.objectInputStream;
    }

    /**
     * Gets object output stream.
     *
     * @return the object output stream
     */
    public ObjectOutputStream getObjectOutputStream() {
        return this.objectOutputStream;
    }

    /**
     * Gets server rsa keys.
     *
     * @return the server rsa keys
     */
    public KeyPair getServerRSAKeys() {
        return this.serverRSAKeys;
    }

    /**
     * Gets server signing keys.
     *
     * @return the server signing keys
     */
    public KeyPair getServerSigningKeys() {
        return this.serverSigningKeys;
    }

    /**
     * The type Builder.
     */
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

        /**
         * Instantiates a new Builder.
         */
        public Builder() {
        }

        /**
         * With socket builder.
         *
         * @param socket the socket
         * @return the builder
         */
        public Builder withSocket(Socket socket) {
            this.socket = socket;
            return this;
        }

        /**
         * With encryption algorithm builder.
         *
         * @param encryptionAlgorithm the encryption algorithm
         * @return the builder
         */
        public Builder withEncryptionAlgorithm(String encryptionAlgorithm) {
            this.encryptionAlgorithm = encryptionAlgorithm;
            return this;
        }

        /**
         * With key size builder.
         *
         * @param keySize the key size
         * @return the builder
         */
        public Builder withKeySize(Integer keySize) {
            this.keySize = keySize;
            return this;
        }

        /**
         * With hashing algorithm builder.
         *
         * @param hashingAlgorithm the hashing algorithm
         * @return the builder
         */
        public Builder withHashingAlgorithm(String hashingAlgorithm) {
            this.hashingAlgorithm = hashingAlgorithm;
            return this;
        }

        /**
         * With encryption algorithm type builder.
         *
         * @param encryptionAlgorithmType the encryption algorithm type
         * @return the builder
         */
        public Builder withEncryptionAlgorithmType(EncryptionAlgorithmType encryptionAlgorithmType) {
            this.encryptionAlgorithmType = encryptionAlgorithmType;
            return this;
        }

        /**
         * With public signing key builder.
         *
         * @param publicSigningKey the public signing key
         * @return the builder
         */
        public Builder withPublicSigningKey(PublicKey publicSigningKey) {
            this.publicSigningKey = publicSigningKey;
            return this;
        }

        /**
         * With public rsa key builder.
         *
         * @param publicRSAKey the public rsa key
         * @return the builder
         */
        public Builder withPublicRSAKey(PublicKey publicRSAKey) {
            this.publicRSAKey = publicRSAKey;
            return this;
        }

        /**
         * With symmetric encryption key builder.
         *
         * @param symmetricEncryptionKey the symmetric encryption key
         * @return the builder
         */
        public Builder withSymmetricEncryptionKey(BigInteger symmetricEncryptionKey) {
            this.symmetricEncryptionKey = symmetricEncryptionKey;
            return this;
        }

        /**
         * With object output stream builder.
         *
         * @param objectOutputStream the object output stream
         * @return the builder
         */
        public Builder withObjectOutputStream(ObjectOutputStream objectOutputStream) {
            this.objectOutputStream = objectOutputStream;
            return this;
        }

        /**
         * With object input stream builder.
         *
         * @param objectInputStream the object input stream
         * @return the builder
         */
        public Builder withObjectInputStream(ObjectInputStream objectInputStream) {
            this.objectInputStream = objectInputStream;
            return this;
        }

        /**
         * With server rsa keys builder.
         *
         * @param keyPair the key pair
         * @return the builder
         */
        public Builder withServerRSAKeys(KeyPair keyPair) {
            this.serverRSAKeys = keyPair;
            return this;
        }

        /**
         * With server signing keys builder.
         *
         * @param keyPair the key pair
         * @return the builder
         */
        public Builder withServerSigningKeys(KeyPair keyPair) {
            this.serverSigningKeys = keyPair;
            return this;
        }

        /**
         * Build client spec.
         *
         * @return the client spec
         */
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