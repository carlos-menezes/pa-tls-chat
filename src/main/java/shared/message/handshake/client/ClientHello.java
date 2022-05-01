package shared.message.handshake.client;

import client.Client;

import java.io.Serializable;

/**
 * {@link ClientHello} is the initial message sent by client in order to initiate secure communication with the server.
 */
public class ClientHello implements Serializable {
    private final String encryptionAlgorithm;
    private final Integer keySize;
    private final String hashingAlgorithm;
    private final String name;

    public ClientHello(Client client) {
        this.encryptionAlgorithm = client.getEncryptionAlgorithm();
        this.keySize = client.getKeySize();
        this.hashingAlgorithm = client.getHashingAlgorithm();
        this.name = client.getName();

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

    @Override
    public String toString() {
        return "ClientHello{" + "encryptionAlgorithm='" + encryptionAlgorithm + '\'' + ", keySize=" + keySize + ", hashingAlgorithm='" + hashingAlgorithm + '\'' + ", name='" + name + '\'' + '}';
    }
}
