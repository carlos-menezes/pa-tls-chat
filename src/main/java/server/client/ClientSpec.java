package server.client;

import shared.encryption.validator.EncryptionAlgorithmType;

import java.net.Socket;

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

    private ClientSpec setSocket(Socket socket) {
        this.socket = socket;
        return this;
    }

    private ClientSpec setEncryptionAlgorithm(String encryptionAlgorithm) {
        this.encryptionAlgorithm = encryptionAlgorithm;
        return this;
    }

    private ClientSpec setKeySize(Integer keySize) {
        this.keySize = keySize;
        return this;
    }

    private ClientSpec setHashingAlgorithm(String hashingAlgorithm) {
        this.hashingAlgorithm = hashingAlgorithm;
        return this;
    }

    public ClientSpec setEncryptionAlgorithmType(EncryptionAlgorithmType encryptionAlgorithmType) {
        this.encryptionAlgorithmType = encryptionAlgorithmType;
        return this;
    }


    public static final class Builder {
        private Socket socket;
        private String encryptionAlgorithm;
        private Integer keySize;
        private String hashingAlgorithm;
        private EncryptionAlgorithmType encryptionAlgorithmType;

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

        public ClientSpec build() {
            ClientSpec clientSpec = new ClientSpec();
            clientSpec.encryptionAlgorithmType = this.encryptionAlgorithmType;
            clientSpec.encryptionAlgorithm = this.encryptionAlgorithm;
            clientSpec.socket = this.socket;
            clientSpec.keySize = this.keySize;
            clientSpec.hashingAlgorithm = this.hashingAlgorithm;
            return clientSpec;
        }
    }
}