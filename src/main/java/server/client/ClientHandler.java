package server.client;

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
import shared.message.handshake.ClientHello;
import shared.message.handshake.ServerError;
import shared.message.handshake.ServerHello;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.lang.reflect.Array;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

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
        while (this.socket.isConnected()) {
            try {
                Object message = this.objectInputStream.readObject();

                if (message instanceof ClientHello clientHello) {
                    this.handleClientHello(clientHello);
                } else {
                    if (message instanceof SealedObject sealedObject) {
                        ClientSpec clientSpec = Server.clients.get(this.name);
                        ClientMessage clientMessage = null;
                        switch (clientSpec.getEncryptionAlgorithmType()) {
                            case SYMMETRIC -> {
                                SecretKeySpec secretKeySpec = SymmetricEncryptionScheme.getSecretKeyFromBytes(
                                        clientSpec.getKeySize(),
                                        clientSpec.getPrivateSharedDHKey()
                                                  .toByteArray(),
                                        clientSpec.getEncryptionAlgorithm());
                                clientMessage = (ClientMessage) sealedObject.getObject(secretKeySpec);
                            }
                            case ASYMMETRIC -> {
                                SecretKeySpec secretKeySpec = SymmetricEncryptionScheme.getSecretKeyFromBytes(
                                        256,
                                        clientSpec.getPrivateSharedDHKey()
                                                  .toByteArray(),
                                        "AES");
                                clientMessage = (ClientMessage) sealedObject.getObject(secretKeySpec);
                            }
                        }

                        this.handleClientMessage(clientMessage);
                    }
                }


            } catch (IOException | ClassNotFoundException | NoSuchAlgorithmException | InvalidKeyException e) {
                break;
            }
        }

        try {
            String leftMessage = Messages.userLeft(this.getName());
            ServerUserStatusMessage serverUserStatusMessage = new ServerUserStatusMessage(leftMessage);
            this.broadcast(serverUserStatusMessage);
            Logger.info(leftMessage);
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            Server.removeClient(this.getName());
        }
    }

    private void broadcast(Serializable message) throws IOException {
        for (String user : Server.clients.keySet()) {
            if (!Objects.equals(user, this.getName())) {
                this.sendMessage(Server.clients.get(user).getObjectOutputStream(), message);
            }
        }
    }

    private void handleClientMessage(ClientMessage clientMessage) throws IOException {
        ServerMessage serverMessage = new ServerMessage(this.getName(), clientMessage.getMessage());
        ArrayList<String> users = new ArrayList<>(clientMessage.getUsers());

        if (users.get(0).equals("broadcast")) {
            this.broadcast(serverMessage);
        } else {
            for (String user : users) {
                try {
                    ClientSpec clientSpec = Server.clients.get(user);
                    SealedObject sealedObject = this.createEncryptedServerMessage(clientSpec, clientMessage);
                    this.sendMessage(clientSpec.getObjectOutputStream(), sealedObject);
                } catch (NullPointerException | NoSuchPaddingException | NoSuchAlgorithmException | IllegalBlockSizeException | InvalidKeyException e) {
                    Logger.error("User does not exist");
                }
            }
        }

    }

    private SealedObject createEncryptedServerMessage(ClientSpec clientSpec, ClientMessage clientMessage) throws
            NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, IOException,
            InvalidKeyException {
        String message = clientMessage.getMessage();
        ServerMessage serverMessage = new ServerMessage(this.name, message);
        String hashingAlgorithm = clientSpec.getHashingAlgorithm();

        // If hashing is supported, verify hash
        if (!hashingAlgorithm.isEmpty()) {
            String hash = HashingEncoder.createDigest(hashingAlgorithm, message);
            serverMessage.setHash(hash);
        }

        SealedObject sealedObject;
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
            default -> throw new IllegalStateException("Unexpected value: " + clientSpec.getEncryptionAlgorithmType());
        }

        return sealedObject;
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
                byte[] encryptedRSAKey = AsymmetricEncryptionScheme.encrypt(publicDHKey.toByteArray(),
                                                                            rsaPrivateKeyWithSupportedSize);
                serverHelloBuilder.withPublicDHKey(new BigInteger(Objects.requireNonNull(encryptedRSAKey)));
            } else {
                serverHelloBuilder.withPublicDHKey(publicDHKey);
            }
            ServerHello serverHello = serverHelloBuilder.build();
            this.sendMessage(this.objectOutputStream, serverHello);

            String joinMessage = Messages.userJoined(this.getName());
            ServerUserStatusMessage serverUserStatusMessage = new ServerUserStatusMessage(joinMessage);
            this.broadcast(serverUserStatusMessage);
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
