package server;

import picocli.CommandLine;
import server.client.ClientHandler;
import server.client.ClientSpec;
import shared.encryption.validator.RSAValidator;
import shared.keys.schemes.AsymmetricEncryptionScheme;

import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.concurrent.Callable;

@CommandLine.Command(name = "server", mixinStandardHelpOptions = true, version = "0.1")
public class Server implements Callable<Integer> {
    private ServerSocket serverSocket;
    public static HashMap<String, ClientSpec> clients;
    public static HashMap<Integer, KeyPair> RSAKeys;

    @CommandLine.Option(names = {"--port"}, description = "Server to run the port on", required = true)
    private Integer port;

    @Override
    public Integer call() throws Exception {
        this.serverSocket = new ServerSocket(this.port);
        Server.clients = new HashMap<>();

        Server.RSAKeys = new HashMap<>();
        Server.populateRSAKeys();

        while (!this.serverSocket.isClosed()) {
            Socket client = this.serverSocket.accept();
            ClientHandler clientHandler = new ClientHandler(client);
            Thread thread = new Thread(clientHandler);
            thread.start();
        }

        return null;
    }

    private static void populateRSAKeys() throws NoSuchAlgorithmException {
        // TODO: loop nos tamanhos das chaves RSA no RSAValidator
        Server.RSAKeys.put(1024, AsymmetricEncryptionScheme.generateKeys(1024));
        Server.RSAKeys.put(2048, AsymmetricEncryptionScheme.generateKeys(2048));
        Server.RSAKeys.put(4096, AsymmetricEncryptionScheme.generateKeys(4096));
    }
}
