package client.protocol;

import client.Client;
import picocli.CommandLine;
import shared.encryption.validator.EncryptionAlgorithmType;
import shared.keys.schemes.DiffieHellman;
import shared.logging.Logger;
import shared.message.handshake.ClientHello;
import shared.message.handshake.ServerError;
import shared.message.handshake.ServerHello;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.PublicKey;
import java.util.concurrent.Callable;

/**
 * The {@link Handshake} class performs the client-side actions of the handshake operation.
 */
public class Handshake implements Callable<Integer> {
    private final Client client;
    private final ObjectOutputStream objectOutputStream;
    private final ObjectInputStream objectInputStream;

    /**
     * Constructs a new {@link Handshake} object.
     *
     * @param client {@link Client} who's performing the handshake
     */
    public Handshake(Client client) {
        this.client = client;
        this.objectInputStream = client.getObjectInputStream();
        this.objectOutputStream = client.getObjectOutputStream();
    }

    /**
     * Performs the handshake protocol.
     * // TODO: Describe the process
     *
     * @return 0 if the operation was performed successfully; 1 otherwise.
     * @throws IOException            Any of the usual Input/Output related exceptions.
     * @throws ClassNotFoundException Class of a serialized object cannot be found.
     */
    @Override
    public Integer call() throws IOException, ClassNotFoundException {

        BigInteger privateDHKey = null;
        BigInteger publicDHKey;

        // 1. Create and send `CLIENT_HELLO`
        ClientHello clientHello = new ClientHello(this.client);
        if (this.client.getEncryptionAlgorithmType() == EncryptionAlgorithmType.SYMMETRIC) {
            // Generate Diffie-Hellman keys for symmetric encryption
            privateDHKey = DiffieHellman.generatePrivateKey();
            publicDHKey = DiffieHellman.generatePublicKey(privateDHKey);
            clientHello.setPublicDiffieHellmanKey(publicDHKey);
        }
        this.sendMessage(clientHello);

        // 2. Receive `SERVER_HELLO` or `SERVER_ERROR`
        Object serverReply = this.receiveMessage();
        if (serverReply instanceof ServerError) {
            Logger.error("Username already in use.");
            return CommandLine.ExitCode.SOFTWARE;
        }

        // At this phase, no other types of message can be sent by the server,
        // so treat the message as `SERVER_HELLO`.
        ServerHello serverHello = (ServerHello) serverReply;
        PublicKey serverSigningKey = serverHello.getPublicSigningKey();

        this.client.setServerSigningKey(serverSigningKey);
        switch (this.client.getEncryptionAlgorithmType()) {
            case SYMMETRIC -> {
                // The computed, shared Diffie-Hellman key is used to derive a key for the chosen symmetric algorithm.
                BigInteger serverPublicDHKey = serverHello.getPublicDiffieHellmanKey();
                BigInteger privateSharedDHKey = DiffieHellman.computePrivateKey(serverPublicDHKey, privateDHKey);
                this.client.setSymmetricEncryptionKey(privateSharedDHKey);
            }
            case ASYMMETRIC -> {
                PublicKey serverPublicRSAKey = serverHello.getPublicRSAKey();
                this.client.setServerRSAKey(serverPublicRSAKey);
            }
        }
        return CommandLine.ExitCode.OK;
    }

    /**
     * Receives an object from the socket.
     *
     * @return received object
     * @throws IOException            Any of the usual Input/Output related exceptions.
     * @throws ClassNotFoundException Class of a serialized object cannot be found.
     */
    private Object receiveMessage() throws IOException, ClassNotFoundException {
        return this.objectInputStream.readObject();
    }

    /**
     * Sends a message to the socket.
     *
     * @param message message to be sent
     * @throws IOException Any of the usual Input/Output related exceptions.
     */
    private void sendMessage(Serializable message) throws IOException {
        this.objectOutputStream.writeObject(message);
        this.objectOutputStream.flush();
    }

}
