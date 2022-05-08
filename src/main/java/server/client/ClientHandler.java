package server.client;

import client.Client;
import org.apache.commons.lang3.SerializationUtils;
import server.Server;
import shared.encryption.validator.EncryptionAlgorithmType;
import shared.hashing.encoder.HashingEncoder;
import shared.keys.schemes.AsymmetricEncryptionScheme;
import shared.keys.schemes.DiffieHellman;
import shared.keys.schemes.SymmetricEncryptionScheme;
import shared.logging.Logger;
import shared.logging.Messages;
import shared.message.communication.ClientMessage;
import shared.message.communication.ServerMessage;
import shared.message.communication.ServerUserStatusMessage;
import shared.message.communication.SignedClientMessage;
import shared.message.handshake.ClientHello;
import shared.message.handshake.ServerError;
import shared.message.handshake.ServerHello;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.*;
import java.util.HashSet;
import java.util.Objects;

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
     * Runs the handshake protocol.
     */
    @Override
    public void run() {
        while (this.socket.isConnected()) {
            try {
                Object message = this.objectInputStream.readObject();

                if (message instanceof ClientHello clientHello) {
                    this.handleClientHello(clientHello);
                } else {
                    if (message instanceof SignedClientMessage signedClientMessage) {
                        ClientSpec clientSpec = Server.clients.get(this.name);
                        // Verifica a autenticidade
                        Signature signature = Signature.getInstance(clientSpec.getHashingAlgorithm().isEmpty() ? "SHA256withRSA": clientSpec.getHashingAlgorithm());
                        signature.initVerify(clientSpec.getPublicSigningKey());
                        signature.update(signedClientMessage.getSealedClientMessageBytes());
                        boolean validSignature = signature.verify(signedClientMessage.getSigningHash());
                        if(!validSignature) {
                            continue;
                        }

                        SealedObject sealedObject = SerializationUtils.deserialize(signedClientMessage.getSealedClientMessageBytes());
                        ClientMessage clientMessage = null;
                        switch (clientSpec.getEncryptionAlgorithmType()) {
                            case SYMMETRIC -> {
                                SecretKeySpec secretKeySpec = SymmetricEncryptionScheme.getSecretKeyFromBytes(
                                        clientSpec.getKeySize(),
                                        clientSpec.getPrivateSharedDHKey()
                                                .toByteArray(),
                                        clientSpec.getEncryptionAlgorithm());
                                clientMessage = (ClientMessage) sealedObject.getObject(secretKeySpec);
                                System.out.println(clientMessage.getMessage());
                            }
                            case ASYMMETRIC -> {
                                clientMessage = (ClientMessage) sealedObject.getObject(this.RSAPrivateKey);
                                System.out.println(clientMessage.getMessage());
                            }
                        }

                        /*this.handleClientMessage(clientMessage);*/
                    }
                }
            } catch (IOException | ClassNotFoundException | NoSuchAlgorithmException | InvalidKeyException e) {
                break;
            } catch (SignatureException e) {
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
        } finally {
            Server.clients.remove(this.name);
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
                this.sendMessage(Server.clients.get(user)
                        .getObjectOutputStream(), message);
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
        HashSet<String> users = new HashSet<>(clientMessage.getUsers());
        if (users.isEmpty()) {
            this.broadcast(serverMessage);
        } else {
            for (String user : users) {
                try {
                    ClientSpec clientSpec = Server.clients.get(user);
                    String messageContent = clientMessage.getMessage();
                    SealedObject sealedObject = this.createEncryptedServerMessage(clientSpec, messageContent);
                    this.sendMessage(clientSpec.getObjectOutputStream(), sealedObject);
                } catch (NullPointerException | NoSuchPaddingException | NoSuchAlgorithmException | IllegalBlockSizeException | InvalidKeyException e) {
                    Logger.error("User does not exist");
                }
            }
        }

    }

    /**
     * Creates a new {@link SealedObject} with the content of a {@link ClientMessage}.
     *
     * @param clientSpec     {@link ClientSpec}
     * @param messageContent content of the message
     * @return an {@link SealedObject} encrypted with the receiver's supported encryption algorithm
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws IllegalBlockSizeException
     * @throws IOException
     * @throws InvalidKeyException
     */
    private SealedObject createEncryptedServerMessage(ClientSpec clientSpec, String messageContent) throws
            NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, IOException,
            InvalidKeyException {
        ServerMessage serverMessage = new ServerMessage(this.name, messageContent);
        String hashingAlgorithm = clientSpec.getHashingAlgorithm();

        // If hashing is supported, create hash
        if (!hashingAlgorithm.isEmpty()) {
            String hash = HashingEncoder.createDigest(hashingAlgorithm, messageContent);
            serverMessage.setHash(hash);
        }

        SealedObject sealedObject = null;
        // Encrypt
        switch (clientSpec.getEncryptionAlgorithmType()) {
            case SYMMETRIC -> {
                Cipher cipher = Cipher.getInstance(clientSpec.getEncryptionAlgorithm());
                byte[] bytes = ByteBuffer.allocate(clientSpec.getKeySize() / 8)
                        .put(clientSpec.getPrivateSharedDHKey()
                                .toByteArray())
                        .array();
                SecretKeySpec secretKeySpec = new SecretKeySpec(bytes, clientSpec.getEncryptionAlgorithm());
                cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
                sealedObject = new SealedObject(serverMessage, cipher);
            }
            case ASYMMETRIC -> {
                Cipher cipher = Cipher.getInstance("AES");
                byte[] bytes = ByteBuffer.allocate(256 / 8)
                        .put(clientSpec.getPrivateSharedDHKey()
                                .toByteArray())
                        .array();
                SecretKeySpec secretKeySpec = new SecretKeySpec(bytes, "AES");
                cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
                sealedObject = new SealedObject(serverMessage, cipher);
            }
        }

        return sealedObject;
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
                    .withPublicSigningKey(message.getPublicSigningKey())
                    .withObjectInputStream(
                            this.objectInputStream)
                    .withObjectOutputStream(
                            this.objectOutputStream);

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
                this.RSAPrivateKey = rsaPrivateKeyWithSupportedSize;
                byte[] encryptedRSAKey = AsymmetricEncryptionScheme.encrypt(publicDHKey.toByteArray(),
                        rsaPrivateKeyWithSupportedSize);
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
