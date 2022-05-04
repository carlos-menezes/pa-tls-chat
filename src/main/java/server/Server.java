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
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.Semaphore;

@CommandLine.Command(name = "server", mixinStandardHelpOptions = true, version = "0.1")
public class Server implements Callable<Integer> {
    private ServerSocket serverSocket;
    public static HashMap<String, ClientSpec> clients;
    public static HashMap<Integer, KeyPair> RSAKeys;
    private static final Semaphore _sem = new Semaphore(1);

    @CommandLine.Option(names = {"--port"}, description = "Server to run the port on", required = true)
    private Integer port;

    @Override
    public Integer call() throws Exception {
        this.serverSocket = new ServerSocket(this.port);
        Server.clients = new HashMap<>();

        Server.RSAKeys = new HashMap<>();
        Server.populateRSAKeys();

        System.out.println("Server running on port " + this.port);

        while (!this.serverSocket.isClosed()) {
            Socket client = this.serverSocket.accept();
            ClientHandler clientHandler = new ClientHandler(client);
            Thread thread = new Thread(clientHandler);
            thread.start();
        }

        return null;
    }

    private static void populateRSAKeys() throws NoSuchAlgorithmException {
        List<Integer> keySizes = new RSAValidator().getKeySizes();
        for (Integer keySize: keySizes) {
            Server.RSAKeys.put(keySize, AsymmetricEncryptionScheme.generateKeys(keySize));
        }
    }

    public static void removeClient(String user) {
        try {
            _sem.acquire();
            Server.clients.remove(user);
        } catch (InterruptedException e) {
            e.printStackTrace();
        } finally {
            _sem.release();
        }
    }
}
