package server.client;

import server.Server;
import shared.encryption.validator.EncryptionAlgorithmType;
import shared.keys.schemes.AsymmetricEncryptionScheme;
import shared.keys.schemes.DiffieHellman;
import shared.logging.Logger;
import shared.logging.Messages;
import shared.message.communication.ClientMessage;
import shared.message.communication.ServerMessage;
import shared.message.handshake.ClientHello;
import shared.message.handshake.ServerError;
import shared.message.handshake.ServerHello;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.PublicKey;
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
                if (message instanceof ClientHello clientHello) {
                    this.handleClientHello(clientHello);
                } else if (message instanceof ClientMessage clientMessage) {
                    this.handleClientMessage(clientMessage);
                } else {
                    Logger.error("An invalid message was received.");
                }
            } catch (IOException | ClassNotFoundException e) {
                break;
            }
        }
        try {
            String leftMessage = Messages.userLeft(this.getName());
            this.broadcast(leftMessage);
            Logger.info(leftMessage);
        } catch (IOException e) {
            e.printStackTrace();
        }
        Server.removeClient(this.getName());
    }

    private void handleClientMessage(ClientMessage clientMessage) throws IOException {
        // 1. Attempt to decrypt the message

        // . Redirect
        redirectMessage(clientMessage);
    }

    private void redirectMessage(ClientMessage message) throws IOException {
        ServerMessage serverMessage = new ServerMessage(this.getName(), message.getMessage());
        ArrayList<String> users = message.getUsers();
        if(users.get(0).equals("broadcast")) {
            this.broadcast(serverMessage);
        } else {
            for (String user : users) {
                try {
                    // TODO: encrypt based on each client and generate hash
                    this.sendMessage(Server.clients.get(user).getObjectOutputStream(), serverMessage);
                } catch (NullPointerException e) {
                    Logger.error("User does not exist");
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

            String joinMessage = Messages.userJoined(message.getName());
            this.broadcast(joinMessage);
            Logger.info(joinMessage);
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
