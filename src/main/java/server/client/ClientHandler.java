package server.client;

import server.Server;
import shared.encryption.decoder.MessageDecoder;
import shared.encryption.encoder.MessageEncoder;
import shared.encryption.validator.EncryptionAlgorithmType;
import shared.encryption.validator.EncryptionValidator;
import shared.keys.schemes.AsymmetricEncryptionScheme;
import shared.keys.schemes.DiffieHellman;
import shared.logging.Logger;
import shared.logging.Messages;
import shared.message.communication.ClientMessage;
import shared.message.communication.ServerMessage;
import shared.message.communication.ServerUserStatusMessage;
import shared.message.communication.SignedMessage;
import shared.message.handshake.ClientHello;
import shared.message.handshake.ServerError;
import shared.message.handshake.ServerHello;
import shared.signing.MessageValidator;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.net.Socket;
import java.security.*;
import java.util.HashSet;
import java.util.Objects;

/**
 * The <code>ClientHandler</code> class represents all the operations to handle the communication with a client
 */
public class ClientHandler implements Runnable {
    private final Socket socket;
    private final ObjectInputStream objectInputStream;
    private final ObjectOutputStream objectOutputStream;
    private String name;
    private PrivateKey RSAPrivateKey;

    /**
     * Constructs a new {@link ClientHandler}.
     *
     * @param socket I/O socket
     * @throws IOException if an I/O error occurs while writing/reading stream header
     */
    public ClientHandler(Socket socket) throws IOException {
        this.socket = socket;
        this.objectInputStream = new ObjectInputStream(this.socket.getInputStream());
        this.objectOutputStream = new ObjectOutputStream(this.socket.getOutputStream());
    }

    /**
     * Runs the handshake protocol and handles the messages.
     */
    @Override
    public void run() {
        while (this.socket.isConnected()) {
            try {
                Object message = this.objectInputStream.readObject();

                if (message instanceof ClientHello clientHello) {
                    this.handleClientHello(clientHello);
                } else {
                    if (message instanceof SignedMessage signedMessage) {
                        ClientSpec clientSpec = Server.clients.get(this.name);
                        boolean validSignature = MessageValidator.validateMessage(clientSpec.getHashingAlgorithm(), clientSpec.getPublicSigningKey(), signedMessage);
                        if (!validSignature) {
                            continue;
                        }

                        ClientMessage clientMessage = null;
                        switch (clientSpec.getEncryptionAlgorithmType()) {
                            case SYMMETRIC -> clientMessage = (ClientMessage) MessageDecoder.decodeMessage(signedMessage, clientSpec.getPrivateSharedDHKey(), clientSpec.getKeySize(), clientSpec.getEncryptionAlgorithm());
                            case ASYMMETRIC -> clientMessage = (ClientMessage) MessageDecoder.decodeMessage(signedMessage, this.RSAPrivateKey, clientSpec.getEncryptionAlgorithm());
                            default -> throw new IllegalStateException("Unexpected value: " + clientSpec.getEncryptionAlgorithmType());
                        }
                        Logger.info(this.name + " sent: \"" + clientMessage.getMessage() + "\" to " + (clientMessage.getUsers().isEmpty() ? "everyone" : "the following users: " + clientMessage.getUsers()));
                        this.handleClientMessage(clientMessage);
                    }
                }
            } catch (IOException | ClassNotFoundException | NoSuchAlgorithmException | InvalidKeyException e) {
                break;
            } catch (SignatureException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException e) {
                e.printStackTrace();
            }
        }

        try {
            String leftMessage = Messages.userLeft(this.name);
            ServerUserStatusMessage serverUserStatusMessage = new ServerUserStatusMessage(leftMessage);
            this.broadcast(serverUserStatusMessage);
            Logger.info(leftMessage);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Broadcasts a message.
     *
     * @param message Message to broadcast.
     * @throws IOException
     */
    private void broadcast(Serializable message) throws IOException {
        for (String user : Server.clients.keySet()) {
            if (!Objects.equals(user, this.name)) {
                this.sendMessage(Server.clients.get(user).getObjectOutputStream(), message);
            }
        }
    }

    /**
     * Handles a {@link ClientMessage}.
     *
     * @param clientMessage message to handle
     * @throws IOException
     */
    private void handleClientMessage(ClientMessage clientMessage) throws IOException {
        ServerMessage serverMessage = new ServerMessage(this.name, clientMessage.getMessage());
        HashSet<String> users;
        users = new HashSet<>(clientMessage.getUsers());

        if (users.isEmpty()) {
            users = new HashSet<>(Server.clients.keySet());
        }
        for (String user : users) {
            // Outra opção seria filtrar o HashSet da condição de cima
            if (!Objects.equals(user, this.name)) {
                try {
                    ClientSpec clientSpec = Server.clients.get(user);

                    EncryptionValidator encryptionValidator = new EncryptionValidator();
                    EncryptionAlgorithmType algorithmType = encryptionValidator.getValidators()
                            .get(clientSpec.getEncryptionAlgorithm())
                            .getType();

                    SignedMessage signedMessage = null;
                    // Encrypt message
                    switch (algorithmType) {
                        case SYMMETRIC -> signedMessage = MessageEncoder.encodeMessage(serverMessage, clientSpec.getEncryptionAlgorithm(), clientSpec.getPrivateSharedDHKey(), clientSpec.getKeySize(), clientSpec.getHashingAlgorithm(), Server.signingKeys.getPrivate());
                        case ASYMMETRIC -> signedMessage = MessageEncoder.encodeMessage(serverMessage, clientSpec.getEncryptionAlgorithm(), Server.RSAKeys.get(clientSpec.getKeySize()).getPrivate(), clientSpec.getHashingAlgorithm(), Server.signingKeys.getPrivate());
                        default -> throw new IllegalStateException("Unexpected value: " + algorithmType);
                    }
                    this.sendMessage(clientSpec.getObjectOutputStream(), signedMessage);
                } catch (NullPointerException | NoSuchPaddingException | NoSuchAlgorithmException | IllegalBlockSizeException | InvalidKeyException e) {
                    Logger.error("User does not exist");
                } catch (SignatureException e) {
                    e.printStackTrace();
                } catch (BadPaddingException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    /**
     * Sends a message through the socket.
     *
     * @param objectOutputStream {@link ObjectOutputStream} to send the message through
     * @param message            {@link shared.message.communication.Message} to be sent
     * @throws IOException
     */
    private void sendMessage(ObjectOutputStream objectOutputStream, Serializable message) throws IOException {
        objectOutputStream.writeObject(message);
        objectOutputStream.flush();
    }

    /**
     * Handles a {@link ClientHello} message.
     *
     * @param message message to be handled
     * @throws IOException
     */
    private void handleClientHello(ClientHello message) throws IOException, NoSuchAlgorithmException {
        // Check if username already exists
        if (Server.clients.containsKey(message.getName())) {
            ServerError serverError = new ServerError(ServerError.USERNAME_IN_USE);
            this.sendMessage(this.objectOutputStream, serverError);
        } else {
            this.name = message.getName();
            BigInteger privateDHKey = DiffieHellman.generatePrivateKey();
            BigInteger publicDHKey = DiffieHellman.generatePublicKey(privateDHKey);

            ClientSpec.Builder clientSpecBuilder = new ClientSpec.Builder().withSocket(this.socket).withEncryptionAlgorithm(message.getEncryptionAlgorithm()).withKeySize(message.getKeySize()).withHashingAlgorithm(message.getHashingAlgorithm()).withEncryptionAlgorithmType(message.getEncryptionAlgorithmType()).withPublicSigningKey(message.getPublicSigningKey()).withObjectInputStream(this.objectInputStream).withObjectOutputStream(this.objectOutputStream);

            if (message.getEncryptionAlgorithmType() == EncryptionAlgorithmType.ASYMMETRIC) {
                clientSpecBuilder.withPublicRSAKey(message.getPublicRSAKey());
            }

            BigInteger sharedPrivateKey = DiffieHellman.computePrivateKey(message.getPublicDHKey(), privateDHKey);
            clientSpecBuilder.withPrivateSharedDHKey(sharedPrivateKey);

            ClientSpec clientSpec = clientSpecBuilder.build();

            Server.clients.put(message.getName(), clientSpec);
            ServerHello.Builder serverHelloBuilder = new ServerHello.Builder();
            serverHelloBuilder.withPublicSigningKey(Server.signingKeys.getPublic());
            if (message.getEncryptionAlgorithmType() == EncryptionAlgorithmType.ASYMMETRIC) {
                Integer clientRSAKeySize = message.getKeySize();
                PublicKey rsaPublicKeyWithSupportedSize = Server.RSAKeys.get(clientRSAKeySize).getPublic();
                serverHelloBuilder.withPublicRSAKey(rsaPublicKeyWithSupportedSize);
                PrivateKey rsaPrivateKeyWithSupportedSize = Server.RSAKeys.get(clientRSAKeySize).getPrivate();
                this.RSAPrivateKey = rsaPrivateKeyWithSupportedSize;
                byte[] encryptedRSAKey = AsymmetricEncryptionScheme.encrypt(publicDHKey.toByteArray(), rsaPrivateKeyWithSupportedSize);
                serverHelloBuilder.withPublicDHKey(new BigInteger(Objects.requireNonNull(encryptedRSAKey)));
            } else {
                serverHelloBuilder.withPublicDHKey(publicDHKey);
            }
            ServerHello serverHello = serverHelloBuilder.build();
            this.sendMessage(this.objectOutputStream, serverHello);

            String joinMessage = Messages.userJoined(this.name);
            ServerUserStatusMessage serverUserStatusMessage = new ServerUserStatusMessage(joinMessage);
            this.broadcast(serverUserStatusMessage);
            Logger.info(joinMessage);
        }
    }
}
