package shared.message.communication;

import java.io.Serializable;

public class SignedMessage implements Serializable {
    private final byte[] sealedMessageBytes;
    private final byte[] signingHash;

    public SignedMessage(byte[] sealedMessageBytes, byte[] signingHash) {
        this.sealedMessageBytes = sealedMessageBytes;
        this.signingHash = signingHash;
    }

    public byte[] getSealedMessageBytes() {
        return sealedMessageBytes;
    }

    public byte[] getSigningHash() {
        return signingHash;
    }
}
