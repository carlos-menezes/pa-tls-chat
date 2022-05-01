package server;

import picocli.CommandLine;
import server.client.ClientHandler;
import server.client.ClientSpec;

import java.net.ServerSocket;
import java.net.Socket;
import java.util.HashMap;
import java.util.concurrent.Callable;

@CommandLine.Command(name = "server", mixinStandardHelpOptions = true, version = "0.1")
public class Server implements Callable<Integer> {
    private ServerSocket serverSocket;
    private HashMap<String, ClientSpec> clients;

    @CommandLine.Option(names = {"--port"}, description = "Server to run the port on", required = true)
    private Integer port;

    @Override
    public Integer call() throws Exception {
        this.serverSocket = new ServerSocket(this.port);
        while (!this.serverSocket.isClosed()) {
            Socket client = this.serverSocket.accept();
            ClientHandler clientHandler = new ClientHandler(client);
            Thread thread = new Thread(clientHandler);
            thread.start();
        }
        return null;
    }
}
