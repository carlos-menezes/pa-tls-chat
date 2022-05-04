package server.client;

import server.Server;
import shared.encryption.validator.EncryptionAlgorithmType;
import shared.encryption.validator.RSAValidator;
import shared.keys.schemes.AsymmetricEncryptionScheme;
import shared.keys.schemes.DiffieHellman;
import shared.message.communication.ClientMessage;
import shared.message.communication.Message;
import shared.message.communication.ServerMessage;
import shared.message.handshake.client.ClientHello;
import shared.message.handshake.server.ServerError;
import shared.message.handshake.server.ServerHello;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAKey;
import java.util.ArrayList;
import java.util.Objects;

public class ClientHandler implements Runnable {
    private final Socket socket;
    private final ObjectInputStream objectInputStream;
    private final ObjectOutputStream objectOutputStream;
    private String name;

    public ClientHandler(Socket socket) throws IOException {
        this.socket = socket;
        this.objectInputStream = new ObjectInputStream(this.socket.getInputStream());
        this.objectOutputStream = new ObjectOutputStream(this.socket.getOutputStream());
    }

    @Override
    public void run() {
        while(this.socket.isConnected()) {
            try {
                Object message = this.objectInputStream.readObject();
                if (message instanceof ClientHello) {
                    this.handleClientHello((ClientHello) message);
                    // TODO: appropriate logger (say something like "@John joined the chat")
                    this.broadcast(this.getName() + ": Joined the chat");
                } else {
                    /*
                    TODO:
                    - receive message
                    - decrypt
                    - check hash
                    - redirectMessage()
                    */
                    ClientMessage msg = (ClientMessage) message;
                    System.out.println(this.getName() + ": " + msg.getMessage());
                    redirectMessage(msg);
                }
            } catch (IOException | ClassNotFoundException e) {
                break;
            }
        }
        // TODO: broadcast that the user disconnected
        Server.removeClient(this.getName());
    }

    private void redirectMessage(ClientMessage message) throws IOException {
        ServerMessage msg = message.parseToServerMessage(this.getName(), "123");
        ArrayList<String> users = message.getUsers();

        if(users.get(0).equals("broadcast")) {
            this.broadcast(msg);
        } else {
            for (String user : users) {
                try {
                    // TODO: encrypt based on each client and generate hash
                    this.sendMessage(Server.clients.get(user).getObjectOutputStream(), msg);
                } catch (NullPointerException e) {
                    // TODO: proper logging
                    System.out.println("User nao existe");
                }
            }
        }

    }

    private void broadcast(Serializable message) throws IOException {
        for (String user : Server.clients.keySet()) {
            if (!Objects.equals(user, this.getName())) {
                // TODO: encrypt based on each client and generate hash
                this.sendMessage(Server.clients.get(user).getObjectOutputStream(), message);
            }
        }
    }

    private void sendMessage(ObjectOutputStream objectOutputStream, Serializable message) throws IOException {
        objectOutputStream.writeObject(message);
        objectOutputStream.flush();
    }

    private void handleClientHello(ClientHello message) throws IOException {
        // Check if username already exists
        if (Server.clients.containsKey(message.getName())) {
            ServerError serverError = new ServerError(ServerError.USERNAME_IN_USE);
            this.sendMessage(this.objectOutputStream, serverError);
        } else {
            this.name = message.getName();
            BigInteger privateDHKey = DiffieHellman.generatePrivateKey();
            BigInteger publicDHKey = DiffieHellman.generatePublicKey(privateDHKey);

            ClientSpec.Builder clientSpecBuilder = new ClientSpec.Builder().withSocket(this.socket)
                                                                           .withEncryptionAlgorithm(
                                                                                   message.getEncryptionAlgorithm())
                                                                           .withKeySize(message.getKeySize())
                                                                           .withHashingAlgorithm(
                                                                                   message.getHashingAlgorithm())
                                                                           .withEncryptionAlgorithmType(
                                                                                   message.getEncryptionAlgorithmType())
                                                                           .withObjectInputStream(this.objectInputStream)
                                                                           .withObjectOutputStream(this.objectOutputStream);

            if (message.getEncryptionAlgorithmType() == EncryptionAlgorithmType.ASYMMETRIC) {
                clientSpecBuilder.withPublicRSAKey(message.getPublicRSAKey());
            }

            BigInteger sharedPrivateKey = DiffieHellman.computePrivateKey(message.getPublicDHKey(), privateDHKey);
            clientSpecBuilder.withPrivateSharedDHKey(sharedPrivateKey);

            ClientSpec clientSpec = clientSpecBuilder.build();

            Server.clients.put(message.getName(), clientSpec);
            ServerHello.Builder serverHelloBuilder = new ServerHello.Builder();
            if (message.getEncryptionAlgorithmType() == EncryptionAlgorithmType.ASYMMETRIC) {
                Integer clientRSAKeySize = message.getKeySize();
                PublicKey rsaPublicKeyWithSupportedSize = Server.RSAKeys.get(clientRSAKeySize)
                                                                        .getPublic();
                serverHelloBuilder.withPublicRSAKey(rsaPublicKeyWithSupportedSize);
                PrivateKey rsaPrivateKeyWithSupportedSize = Server.RSAKeys.get(clientRSAKeySize)
                                                                          .getPrivate();
                byte[] encryptedRSAKey = AsymmetricEncryptionScheme.encrypt(publicDHKey.toByteArray(),
                                                                            rsaPrivateKeyWithSupportedSize);
                serverHelloBuilder.withPublicDHKey(new BigInteger(Objects.requireNonNull(encryptedRSAKey)));
            } else {
                serverHelloBuilder.withPublicDHKey(publicDHKey);
            }
            ServerHello serverHello = serverHelloBuilder.build();
            this.sendMessage(this.objectOutputStream, serverHello);
        }
    }

    public String getName() {
        return name;
    }

    public ClientHandler setName(String name) {
        this.name = name;
        return this;
    }
}
