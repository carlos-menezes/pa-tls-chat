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
    private final PublicKey publicSigningKey;
    private final PublicKey publicRSAKey;

    /**
     * Creates a new <code>ClientHello</code> object by specifying the client.
     *
     * @param client Client from which the <code>ClientHello</code> will be sent from
     */
    public ClientHello(Client client) {
        this.encryptionAlgorithm = client.getEncryptionAlgorithm();
        this.keySize = client.getKeySize();
        this.hashingAlgorithm = client.getHashingAlgorithm();
        this.name = client.getName();
        this.encryptionAlgorithmType = client.getEncryptionAlgorithmType();
        this.publicSigningKey = client.getSigningKeys().getPublic();

        if (this.encryptionAlgorithmType == EncryptionAlgorithmType.ASYMMETRIC) {
            this.publicRSAKey = client.getRSAKeys().getPublic();
        } else {
            this.publicRSAKey = null;
        }
    }

    /**
     * Returns the client's encryption algorithm
     *
     * @return Client's encryption algorithm
     */
    public String getEncryptionAlgorithm() {
        return this.encryptionAlgorithm;
    }

    /**
     * Return the client's encryption key size
     *
     * @return Client's encryption key size
     */
    public Integer getKeySize() {
        return this.keySize;
    }

    /**
     * Return the client's hashing algorithm
     *
     * @return Client's hashing algorithm
     */
    public String getHashingAlgorithm() {
        return this.hashingAlgorithm;
    }

    /**
     * Returns the client's name
     *
     * @return Client's name
     */
    public String getName() {
        return this.name;
    }

    /**
     * Returns the client's encryption algorithm type
     *
     * @return Client's encryption algorithm type
     */
    public EncryptionAlgorithmType getEncryptionAlgorithmType() {
        return this.encryptionAlgorithmType;
    }

    /**
     * Returns the client's public Diffie-Hellman key
     *
     * @return Client's public Diffie-Hellman key
     */
    public BigInteger getPublicDHKey() {
        return this.publicDHKey;
    }

    /**
     * Returns the client's public signing key
     *
     * @return Client's public signing key
     */
    public PublicKey getPublicSigningKey() {
        return this.publicSigningKey;
    }

    /**
     * Returns the client's public RSA key
     *
     * @return Client's public RSA key
     */
    public PublicKey getPublicRSAKey() {
        return this.publicRSAKey;
    }

    /**
     * Method that sets the client's public Diffie-Hellman public key
     *
     * @param publicDHKey Client's public Diffie-Hellman public key
     */
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
                ", publicSigningKey=" + publicSigningKey +
                ", publicDHKey=" + publicDHKey +
                ", publicRSAKey=" + publicRSAKey +
                '}';
    }
}
