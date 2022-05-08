package shared.message.communication;

import java.io.Serializable;

public class SignedClientMessage implements Serializable {
    private final byte[] sealedClientMessageBytes;
    private final byte[] signingHash;

    public SignedClientMessage(byte[] sealedClientMessageBytes, byte[] signingHash) {
        this.sealedClientMessageBytes = sealedClientMessageBytes;
        this.signingHash = signingHash;
    }

    public byte[] getSealedClientMessageBytes() {
        return sealedClientMessageBytes;
    }

    public byte[] getSigningHash() {
        return signingHash;
    }
}
