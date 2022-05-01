package server.client;

import java.net.Socket;

/**
 * The <code>ClientSpec</code> class represents all the characteristics that a client will
 * have that are relevant to the server.
 * These characteristics are the socket connection, encryption algorithm used by the client,
 * key size for the encryption and the hashing algorithm used.
 */
public class ClientSpec {

    private Socket socket;

    /**
     * Constructs a new {@link ClientSpec} object.
     */
    public ClientSpec() {
    }

    /**
     * Gets the {@link #socket};
     *
     * @return value of {@link #socket}
     */
    public Socket getSocket() {
        return this.socket;
    }

    public void setSocket(Socket socket) {
        this.socket = socket;
    }
}