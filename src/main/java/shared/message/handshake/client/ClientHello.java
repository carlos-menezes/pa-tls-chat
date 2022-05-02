package shared.message.handshake.client;

import client.Client;
import shared.encryption.validator.EncryptionAlgorithmType;

import java.io.Serializable;
import java.math.BigInteger;

/**
 * {@link ClientHello} is the initial message sent by client in order to initiate secure communication with the server.
 */
public class ClientHello implements Serializable {
    private final String encryptionAlgorithm;
    private final Integer keySize;
    private final String hashingAlgorithm;
    private final String name;
    private final EncryptionAlgorithmType encryptionAlgorithmType;

    public ClientHello(Client client) {
        this.encryptionAlgorithm = client.getEncryptionAlgorithm();
        this.keySize = client.getKeySize();
        this.hashingAlgorithm = client.getHashingAlgorithm();
        this.name = client.getName();
        this.encryptionAlgorithmType = client.getEncryptionAlgorithmType();
    }

    public String getEncryptionAlgorithm() {
        return encryptionAlgorithm;
    }

    public Integer getKeySize() {
        return keySize;
    }

    public String getHashingAlgorithm() {
        return hashingAlgorithm;
    }

    public String getName() {
        return name;
    }

    public EncryptionAlgorithmType getEncryptionAlgorithmType() {
        return encryptionAlgorithmType;
    }


    @Override
    public String toString() {
        return "ClientHello{" +
                "encryptionAlgorithm='" + encryptionAlgorithm + '\'' +
                ", keySize=" + keySize +
                ", hashingAlgorithm='" + hashingAlgorithm + '\'' +
                ", name='" + name + '\'' +
                ", encryptionAlgorithmType=" + encryptionAlgorithmType +
                '}';
    }
}
