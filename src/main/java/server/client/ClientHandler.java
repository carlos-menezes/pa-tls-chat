package server.client;

import server.Server;
import shared.encryption.codec.Decoder;
import shared.keys.schemes.AsymmetricEncryptionScheme;
import shared.keys.schemes.DiffieHellman;
import shared.logging.Logger;
import shared.logging.Messages;
import shared.message.communication.ClientMessage;
import shared.message.communication.ServerMessage;
import shared.message.communication.ServerUserStatusMessage;
import shared.message.handshake.ClientHello;
import shared.message.handshake.ServerError;
import shared.message.handshake.ServerHello;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.HashSet;
import java.util.Objects;

public class ClientHandler implements Runnable {
    private final Socket socket;
    private final ObjectInputStream objectInputStream;
    private final ObjectOutputStream objectOutputStream;
    private String name;

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
                } else if (message instanceof ClientMessage clientMessage) {
                    this.handleClientMessage(clientMessage);
                }
            } catch (IOException | ClassNotFoundException | NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | SignatureException e) {
                e.printStackTrace();
                break;
            }
        }

        try {
            Server.clients.remove(this.name);
            String leftMessage = Messages.userLeft(this.name);
            ServerUserStatusMessage serverUserStatusMessage = new ServerUserStatusMessage(leftMessage);
            this.broadcast(serverUserStatusMessage);
            Logger.info(leftMessage);
        } catch (IOException ex) {
            ex.printStackTrace();
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
     * @throws IOException
     */
    private void handleClientMessage(ClientMessage clientMessage) throws IOException, NoSuchAlgorithmException,
            SignatureException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException,
            BadPaddingException {
        ClientSpec clientSpec = Server.clients.get(this.name);

        // Decode the content of the message
        byte[] decodedContent = Decoder.decodeMessage(clientMessage.getMessage(), clientSpec);
        boolean validSignature = Decoder.validateSignature(decodedContent, clientSpec.getHashingAlgorithm(),
                                                           clientSpec.getPublicSigningKey(),
                                                           clientMessage.getSignature());

        // Verify if hashes match
        if (!validSignature) {
            Logger.error("Hashes do not match");
            return;
        }

        // List of recipients
        HashSet<String> recipients = new HashSet<>(clientMessage.getUsers());

        String incomingMessageLog = String.format("%s sent `%s` to [%s]", this.name, new String(decodedContent),
                                                  recipients.isEmpty() ? "everyone" : String.join(",", recipients));
        Logger.info(incomingMessageLog);

        if (recipients.isEmpty()) {
            recipients = new HashSet<>(Server.clients.keySet());
        }
        recipients.stream().filter(user -> !user.equals(this.name)).forEach(user -> {
            try {
                ClientSpec userSpec = Server.clients.get(user);
                ServerMessage serverMessage = new ServerMessage(this.name, new String(decodedContent), userSpec);
                this.sendMessage(userSpec.getObjectOutputStream(), serverMessage);
            } catch (NullPointerException e) {
                String error = String.format("User %s does not exist.", user);
                Logger.error(error);
            } catch (BadPaddingException | IOException | NoSuchPaddingException | NoSuchAlgorithmException | IllegalBlockSizeException | InvalidKeyException | SignatureException e) {
                e.printStackTrace();
            }
        });
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
            // Generate Diffie-Hellman keys for symmetric encryption
            BigInteger privateDiffieHellmanKey = DiffieHellman.generatePrivateKey();
            BigInteger publicDiffieHellmanKey = DiffieHellman.generatePublicKey(privateDiffieHellmanKey);
            ClientSpec.Builder clientSpecBuilder = new ClientSpec.Builder().withSocket(this.socket)
                                                                           .withEncryptionAlgorithmType(
                                                                                   message.getEncryptionAlgorithmType())
                                                                           .withEncryptionAlgorithm(
                                                                                   message.getEncryptionAlgorithm())
                                                                           .withServerSigningKeys(
                                                                                   AsymmetricEncryptionScheme.generateKeys(
                                                                                           4096)).withPublicSigningKey(
                            message.getPublicSigningKey()).withHashingAlgorithm(message.getHashingAlgorithm())
                                                                           .withKeySize(message.getKeySize())
                                                                           .withObjectInputStream(
                                                                                   this.objectInputStream)
                                                                           .withObjectOutputStream(
                                                                                   this.objectOutputStream);

            switch (message.getEncryptionAlgorithmType()) {
                case SYMMETRIC -> {
                    // Compute a shared private key from the incoming message's public DH key and the generated
                    // private key
                    BigInteger sharedPrivateKey = DiffieHellman.computePrivateKey(message.getPublicDiffieHellmanKey(),
                                                                                  privateDiffieHellmanKey);
                    clientSpecBuilder.withSymmetricEncryptionKey(sharedPrivateKey);
                }
                case ASYMMETRIC -> {
                    // Assign the client's public RSA key to the ClientSpec object
                    clientSpecBuilder.withPublicRSAKey(message.getPublicRSAKey());

                    // The server must now generate a new key pair to communicate with this client.
                    Integer keySize = message.getKeySize();
                    KeyPair serverRSAKeys = AsymmetricEncryptionScheme.generateKeys(keySize);
                    clientSpecBuilder.withServerRSAKeys(serverRSAKeys);
                }
            }
            ClientSpec clientSpec = clientSpecBuilder.build();
            Server.clients.put(message.getName(), clientSpec);

            ServerHello.Builder serverHelloBuilder = new ServerHello.Builder().withPublicSigningKey(
                    clientSpec.getServerSigningKeys().getPublic());

            switch (message.getEncryptionAlgorithmType()) {
                case SYMMETRIC -> // Send the generated public DH key to the client, so it can compute the shared key.
                        serverHelloBuilder.withPublicDiffieHellmanKey(publicDiffieHellmanKey);
                case ASYMMETRIC -> // Send the server's public RSA key
                        serverHelloBuilder.withPublicRSAKey(clientSpec.getServerRSAKeys().getPublic());
            }
            ServerHello serverHello = serverHelloBuilder.build();
            this.sendMessage(this.objectOutputStream, serverHello);

            // Broadcast the join message to every user
            String joinMessage = Messages.userJoined(this.name);
            ServerUserStatusMessage serverUserStatusMessage = new ServerUserStatusMessage(joinMessage);
            this.broadcast(serverUserStatusMessage);
            Logger.info(joinMessage);
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
}
