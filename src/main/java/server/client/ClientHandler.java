package server.client;

import org.apache.commons.lang3.SerializationUtils;
import server.Server;
import shared.encryption.validator.EncryptionAlgorithmType;
import shared.encryption.validator.EncryptionValidator;
import shared.hashing.encoder.HashingEncoder;
import shared.keys.schemes.AsymmetricEncryptionScheme;
import shared.keys.schemes.DiffieHellman;
import shared.keys.schemes.SymmetricEncryptionScheme;
import shared.logging.Logger;
import shared.logging.Messages;
import shared.message.communication.ClientMessage;
import shared.message.communication.ServerMessage;
import shared.message.communication.ServerUserStatusMessage;
import shared.message.communication.SignedMessage;
import shared.message.handshake.ClientHello;
import shared.message.handshake.ServerError;
import shared.message.handshake.ServerHello;
import shared.signing.MessageSigner;
import shared.signing.MessageValidator;

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
import java.util.Base64;
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
                            case SYMMETRIC -> {
                                SealedObject sealedObject = SerializationUtils.deserialize(signedMessage.getEncryptedMessageBytes());
                                SecretKeySpec secretKeySpec = SymmetricEncryptionScheme.getSecretKeyFromBytes(clientSpec.getKeySize(), clientSpec.getPrivateSharedDHKey().toByteArray(), clientSpec.getEncryptionAlgorithm());
                                clientMessage = (ClientMessage) sealedObject.getObject(secretKeySpec);
                            }
                            case ASYMMETRIC -> {
                                clientMessage = SerializationUtils.deserialize(signedMessage.getEncryptedMessageBytes());
                                byte[] encryptedMessageBytes = Base64.getDecoder().decode(clientMessage.getMessage());
                                Cipher decryptCipher = Cipher.getInstance("RSA");
                                decryptCipher.init(Cipher.DECRYPT_MODE, this.RSAPrivateKey);
                                byte[] decryptedMessageBytes = decryptCipher.doFinal(encryptedMessageBytes);
                                clientMessage.setMessage(new String(decryptedMessageBytes));
                            }
                        }
                        Logger.info(this.name + " sent: \"" + clientMessage.getMessage() + "\" to " + (clientMessage.getUsers().isEmpty() ? "everyone" : "the following users: " + clientMessage.getUsers()));
                        this.handleClientMessage(clientMessage);
                    }
                }
            } catch (IOException | ClassNotFoundException | NoSuchAlgorithmException | InvalidKeyException e) {
                break;
            } catch (SignatureException e) {
                e.printStackTrace();
            } catch (NoSuchPaddingException e) {
                e.printStackTrace();
            } catch (IllegalBlockSizeException e) {
                e.printStackTrace();
            } catch (BadPaddingException e) {
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
                    SignedMessage signedMessage = null;
                    ClientSpec clientSpec = Server.clients.get(user);

                    EncryptionValidator encryptionValidator = new EncryptionValidator();
                    EncryptionAlgorithmType algorithmType = encryptionValidator.getValidators()
                            .get(clientSpec.getEncryptionAlgorithm())
                            .getType();

                    switch (algorithmType) {
                        case SYMMETRIC -> {
                            byte[] sharedKeyBytes = clientSpec.getPrivateSharedDHKey().toByteArray();
                            byte[] bytes = ByteBuffer.allocate(clientSpec.getKeySize() / 8).put(sharedKeyBytes).array();
                            SecretKeySpec secretKey = new SecretKeySpec(bytes, clientSpec.getEncryptionAlgorithm());
                            Cipher cipher = Cipher.getInstance(clientSpec.getEncryptionAlgorithm());
                            cipher.init(Cipher.ENCRYPT_MODE, secretKey);


                            SealedObject sealedObject = new SealedObject(serverMessage, cipher);

                            byte[] sealedObjectBytes = SerializationUtils.serialize(sealedObject);
                            signedMessage = MessageSigner.signMessage(clientSpec.getHashingAlgorithm(), Server.signingKeys.getPrivate(), sealedObjectBytes);
                        }
                        case ASYMMETRIC -> {
                            Cipher cipher = Cipher.getInstance(clientSpec.getEncryptionAlgorithm());
                            cipher.init(Cipher.ENCRYPT_MODE, Server.RSAKeys.get(clientSpec.getKeySize()).getPrivate());
                            byte[] encryptedServerMessageBytes = cipher.doFinal(serverMessage.getMessage().getBytes());
                            serverMessage.setMessage(Base64.getEncoder().encodeToString(encryptedServerMessageBytes));

                            byte[] serverMessageBytes = SerializationUtils.serialize(serverMessage);
                            signedMessage = MessageSigner.signMessage(clientSpec.getHashingAlgorithm(), Server.signingKeys.getPrivate(), serverMessageBytes);
                        }
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
    private SealedObject createEncryptedServerMessage(ClientSpec clientSpec, String messageContent) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, IOException, InvalidKeyException {
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
                byte[] bytes = ByteBuffer.allocate(clientSpec.getKeySize() / 8).put(clientSpec.getPrivateSharedDHKey().toByteArray()).array();
                SecretKeySpec secretKeySpec = new SecretKeySpec(bytes, clientSpec.getEncryptionAlgorithm());
                cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
                sealedObject = new SealedObject(serverMessage, cipher);
            }
            case ASYMMETRIC -> {
                Cipher cipher = Cipher.getInstance("AES");
                byte[] bytes = ByteBuffer.allocate(256 / 8).put(clientSpec.getPrivateSharedDHKey().toByteArray()).array();
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
