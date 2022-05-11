package shared.message.handshake;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.PublicKey;

/**
 * {@link ServerHello} is the initial message sent by client in order to initiate secure communication with the server.
 */
public class ServerHello implements Serializable {

    private BigInteger publicDHKey;
    private PublicKey publicSigningKey;
    private PublicKey publicRSAKey;

    /**
     * Returns the server public Diffie-Hellman key
     *
     * @return Server public Diffie-Hellman key
     */
    public BigInteger getPublicDHKey() {
        return publicDHKey;
    }

    /**
     * Returns the server public signing key
     *
     * @return Server public signing key
     */
    public PublicKey getPublicSigningKey() {
        return publicSigningKey;
    }

    /**
     * Returns the server public RSA key
     *
     * @return Server public RSA key
     */
    public PublicKey getPublicRSAKey() {
        return publicRSAKey;
    }

    @Override
    public String toString() {
        return "ServerHello{" +
                "publicDHKey=" + publicDHKey +
                ", publicRSAKey=" + publicRSAKey +
                '}';
    }

    public static final class Builder {
        private BigInteger publicDHKey;
        private PublicKey publicSigningKey;
        private PublicKey publicRSAKey;

        public Builder() {
        }


        public Builder withPublicDHKey(BigInteger publicDHKey) {
            this.publicDHKey = publicDHKey;
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

        public ServerHello build() {
            ServerHello serverHello = new ServerHello();
            serverHello.publicRSAKey = this.publicRSAKey;
            serverHello.publicSigningKey = this.publicSigningKey;
            serverHello.publicDHKey = this.publicDHKey;
            return serverHello;
        }
    }
}
