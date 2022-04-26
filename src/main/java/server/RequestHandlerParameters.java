package server;

import java.net.Socket;

/**
 * The <code>RequestHandlerParameters</code> class represents all the parameters
 * of a connection/request.
 */
public class RequestHandlerParameters {
    private final Socket socket;
    private final int port;

    /**
     * Creates a new <code>RequestHandlerParameters</code> object by specifying all its attributes.
     *
     * @param socket socket connection
     * @param port port number
     */
    public RequestHandlerParameters(Socket socket, int port) {
        this.socket = socket;
        this.port = port;
    }

    /**
     * Returns the socket connection
     *
     * @return socket connection
     */
    public Socket getSocket() { return socket; }

    /**
     * Returns the port number
     *
     * @return port number
     */
    public int getPort() { return port; }
}