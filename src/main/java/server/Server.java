package server;

import picocli.CommandLine;
import server.client.ClientHandler;
import server.client.ClientSpec;
import shared.logging.Logger;

import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The <code>Server</code> class represents the server from whom the clients are going to connect to
 */
@CommandLine.Command(name = "server", mixinStandardHelpOptions = true, version = "0.1")
public class Server implements Callable<Integer> {
    public static ConcurrentHashMap<String, ClientSpec> clients;

    @CommandLine.Option(names = {"-p", "--port"}, description = "Server to run the port on", required = true)
    private Integer port;

    @Override
    public Integer call() throws Exception {
        ServerSocket serverSocket = new ServerSocket(this.port);
        Server.clients = new ConcurrentHashMap<>();

        Logger.info(String.format("Server started on localhost:%d", this.port));

        while (!serverSocket.isClosed()) {
            Socket client = serverSocket.accept();
            ClientHandler clientHandler = new ClientHandler(client);
            Thread thread = new Thread(clientHandler);
            thread.start();
        }

        return null;
    }


    /**
     * Gets port.
     *
     * @return the port
     */
    public Integer getPort() {
        return port;
    }
}
