package server.client;

import server.Server;
import shared.message.handshake.client.ClientHello;
import shared.message.handshake.server.ServerError;
import shared.message.handshake.server.ServerHello;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.net.Socket;

public class ClientHandler implements Runnable {
    private final Socket socket;
    private final ObjectInputStream objectInputStream;
    private final ObjectOutputStream objectOutputStream;

    public ClientHandler(Socket socket) throws IOException {
        this.socket = socket;
        this.objectInputStream = new ObjectInputStream(this.socket.getInputStream());
        this.objectOutputStream = new ObjectOutputStream(this.socket.getOutputStream());
    }

    @Override
    public void run() {
        try {
            Object message = this.objectInputStream.readObject();
            System.out.println(message.toString());
            if (message instanceof ClientHello) {
                this.handleClientHello((ClientHello) message);
            }
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
    }

    private void sendMessage(Serializable message) throws IOException {
        this.objectOutputStream.writeObject(message);
        this.objectOutputStream.flush();
    }

    private void handleClientHello(ClientHello message) throws IOException {
        // Check if username already exists
        if (Server.clients.containsKey(message.getName())) {
            ServerError serverError = new ServerError(ServerError.USERNAME_IN_USE);
            this.sendMessage(serverError);
        } else {
            ClientSpec clientSpec = new ClientSpec.Builder()
                    .withSocket(this.socket)
                    .withEncryptionAlgorithm(message.getEncryptionAlgorithm())
                    .withKeySize(message.getKeySize())
                    .withHashingAlgorithm(message.getHashingAlgorithm())
                    .withEncryptionAlgorithmType(message.getEncryptionAlgorithmType())
                    .build();

            Server.clients.put(message.getName(), clientSpec);
            // TODO: SERVER_HELLO IS NOT COMPLETE
            ServerHello serverHello = new ServerHello();
        }
    }
}
