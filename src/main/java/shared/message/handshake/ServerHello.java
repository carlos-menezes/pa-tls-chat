package shared.message.handshake;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.PublicKey;

public class ServerHello implements Serializable {

    private BigInteger publicDHKey;
    private PublicKey publicSigningKey;
    private PublicKey publicRSAKey;

    public BigInteger getPublicDHKey() {
        return publicDHKey;
    }

    public PublicKey getPublicSigningKey() {
        return publicSigningKey;
    }

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
