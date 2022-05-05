package shared.message.handshake;

import client.Client;
import shared.encryption.validator.EncryptionAlgorithmType;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.PublicKey;

/**
 * {@link ClientHello} is the initial message sent by client in order to initiate secure communication with the server.
 */
public class ClientHello implements Serializable {
    private final String encryptionAlgorithm;
    private final Integer keySize;
    private final String hashingAlgorithm;
    private final String name;
    private final EncryptionAlgorithmType encryptionAlgorithmType;
    private BigInteger publicDHKey;
    private final PublicKey publicRSAKey;

    public ClientHello(Client client) {
        this.encryptionAlgorithm = client.getEncryptionAlgorithm();
        this.keySize = client.getKeySize();
        this.hashingAlgorithm = client.getHashingAlgorithm();
        this.name = client.getName();
        this.encryptionAlgorithmType = client.getEncryptionAlgorithmType();

        if (this.encryptionAlgorithmType == EncryptionAlgorithmType.ASYMMETRIC) {
            this.publicRSAKey = client.getRSAKeys().getPublic();
        } else {
            this.publicRSAKey = null;
        }
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

    public String getName() {
        return this.name;
    }

    public EncryptionAlgorithmType getEncryptionAlgorithmType() {
        return this.encryptionAlgorithmType;
    }

    public BigInteger getPublicDHKey() {
        return this.publicDHKey;
    }

    public PublicKey getPublicRSAKey() {
        return this.publicRSAKey;
    }

    public void setPublicDHKey(BigInteger publicDHKey) {
        this.publicDHKey = publicDHKey;
    }

    @Override
    public String toString() {
        return "ClientHello{" +
                "encryptionAlgorithm='" + encryptionAlgorithm + '\'' +
                ", keySize=" + keySize +
                ", hashingAlgorithm='" + hashingAlgorithm + '\'' +
                ", name='" + name + '\'' +
                ", encryptionAlgorithmType=" + encryptionAlgorithmType +
                ", publicDHKey=" + publicDHKey +
                ", publicRSAKey=" + publicRSAKey +
                '}';
    }
}
