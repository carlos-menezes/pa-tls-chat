package server.client;

import server.Server;
import shared.encryption.validator.EncryptionAlgorithmType;
import shared.encryption.validator.RSAValidator;
import shared.keys.schemes.AsymmetricEncryptionScheme;
import shared.keys.schemes.DiffieHellman;
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
                    // TODO: broadcast to say that the user joined
                } else {
                    /*
                    TODO:
                    - receive ClientMessage
                    - make hashing and encryption conversions
                    - send ServerMessage to clients
                     */

                    System.out.println(this.getName() + ": " + message);
                }
            } catch (IOException | ClassNotFoundException e) {
                break;
            }
        }
        // TODO: broadcast that the user disconnected
        Server.removeClient(this.getName());
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
                                                                                   message.getEncryptionAlgorithmType());

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
            this.sendMessage(serverHello);
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
