package server;

import config.Config;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

/**
 * The <code>Server</code> class represents the http server
 */
public class Server {

    private final ServerSocket serverSocket;
    private final Config config;

    /**
     * Creates a new <code>Server</code> object by passing a config object as a parameter
     *
     * @param config server config
     * @throws IOException when an error creating a server socket occurs
     */
    public Server(Config config) throws IOException {
        this.config = config;
        this.serverSocket = new ServerSocket(getPort());
    }

    /**
     * Method that starts the http server
     *
     * @throws IOException when an error with the server socket occurs
     */
    public void run() throws IOException, InterruptedException {
        System.out.println("Server initialized on http://localhost:" + this.serverSocket.getLocalPort());
        while (serverSocket.isBound() && !serverSocket.isClosed()) {
            Socket socket = serverSocket.accept();
            RequestHandlerParameters params = new RequestHandlerParameters(socket, getPort());
            RequestHandler handler = new RequestHandler(params);
            Thread handlerThread = new Thread(handler);
            handlerThread.start();
        }
    }

    /**
     * Returns the port number from the config object parsed to an integer.
     *
     * @return port number
     */
    private int getPort() {
        return Integer.parseInt(config.getValue("server.port"));
    }
}