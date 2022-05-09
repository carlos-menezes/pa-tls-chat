package server;

import picocli.CommandLine;
import server.client.ClientHandler;
import server.client.ClientSpec;
import shared.encryption.validator.RSAValidator;
import shared.keys.schemes.AsymmetricEncryptionScheme;
import shared.logging.Logger;

import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;

@CommandLine.Command(name = "server", mixinStandardHelpOptions = true, version = "0.1")
public class Server implements Callable<Integer> {
    public static ConcurrentHashMap<String, ClientSpec> clients;
    public static KeyPair signingKeys;
    public static HashMap<Integer, KeyPair> RSAKeys;

    @CommandLine.Option(names = {"--port"}, description = "Server to run the port on", required = true)
    private Integer port;

    private static void populateRSAKeys() throws NoSuchAlgorithmException {
        List<Integer> keySizes = new RSAValidator().getKeySizes();
        for (Integer keySize : keySizes) {
            Server.RSAKeys.put(keySize, AsymmetricEncryptionScheme.generateKeys(keySize));
        }
    }

    @Override
    public Integer call() throws Exception {
        ServerSocket serverSocket = new ServerSocket(this.port);
        Server.clients = new ConcurrentHashMap<>();
        // Generates Asymmetric KeyPair for signing purposes
        signingKeys = AsymmetricEncryptionScheme.generateKeys(4096);
        Server.RSAKeys = new HashMap<>();
        Server.populateRSAKeys();

        Logger.info(String.format("Server started on localhost:%d", this.port));

        while (!serverSocket.isClosed()) {
            Socket client = serverSocket.accept();
            ClientHandler clientHandler = new ClientHandler(client);
            Thread thread = new Thread(clientHandler);
            thread.start();
        }

        return null;
    }
}
