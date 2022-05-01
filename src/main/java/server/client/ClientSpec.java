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
    // TODO: Add Encryption Alg, key size and hash alg
    // maybe add the public key of the client

    /**
     * Creates a new <code>ClientSpec</code> object by specifying the client's socket
     * connection, encryption algorithm, key size for the encryption algorithm and
     * the hashing algorithm used.
     *
     * @param socket Client's socket connection
     */
    public ClientSpec(Socket socket) {
        this.socket = socket;
    }

    /**
     * Method that returns the client's socket connection.
     *
     * @return Client's socket connection
     */
    public Socket getSocket() {
        return this.socket;
    }
}