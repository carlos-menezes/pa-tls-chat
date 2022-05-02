package client.protocol;

import client.Client;
import picocli.CommandLine;
import shared.encryption.validator.EncryptionAlgorithmType;
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
import java.util.Objects;
import java.util.concurrent.Callable;

public class Handshake implements Callable<Integer> {
    private final Client client;
    private final ObjectOutputStream objectOutputStream;
    private final ObjectInputStream objectInputStream;

    public Handshake(Client client) throws IOException {
        this.client = client;
        this.objectOutputStream = new ObjectOutputStream(this.client.getSocket()
                                                                    .getOutputStream());
        this.objectInputStream = new ObjectInputStream(this.client.getSocket()
                                                                  .getInputStream());
    }

    @Override
    public Integer call() throws Exception {
        // Generate DH keys
        BigInteger privateDHKey = DiffieHellman.generatePrivateKey();
        BigInteger publicDHKey = DiffieHellman.generatePublicKey(privateDHKey);

        // 1. Create and send `CLIENT_HELLO`
        ClientHello clientHello = new ClientHello(this.client);
        clientHello.setPublicDHKey(publicDHKey);
        this.sendMessage(clientHello);

        // 2. Receive `SERVER_HELLO` or `SERVER_ERROR`
        Object serverReply = this.receiveMessage();
        if (serverReply instanceof ServerError) {
            // TODO: appropriate logging
            System.out.println("ERROR: username already in use");
            return CommandLine.ExitCode.SOFTWARE;
        }

        // At this phase, no other types of message can be sent by the server,
        // so treat the message as `SERVER_HELLO`.
        BigInteger privateSharedDHKey;
        ServerHello serverHello = (ServerHello) serverReply;
        BigInteger serverPublicDHKey = serverHello.getPublicDHKey();

        if (this.client.getEncryptionAlgorithmType() == EncryptionAlgorithmType.ASYMMETRIC) {
            this.client.setServerRSAKey(serverHello.getPublicRSAKey());
            byte[] decryptedServerPublicDHKey = AsymmetricEncryptionScheme.decrypt(
                    serverPublicDHKey.toByteArray(), this.client.getServerRSAKey());
            privateSharedDHKey = DiffieHellman.computePrivateKey(
                    new BigInteger(Objects.requireNonNull(decryptedServerPublicDHKey)), privateDHKey);
        } else {
            privateSharedDHKey = DiffieHellman.computePrivateKey(serverPublicDHKey, privateDHKey);
        }
        this.client.setPrivateSharedDHKey(privateSharedDHKey);

        return CommandLine.ExitCode.OK;
    }

    private Object receiveMessage() throws IOException, ClassNotFoundException {
        return this.objectInputStream.readObject();
    }

    private void sendMessage(Serializable message) throws IOException {
        this.objectOutputStream.writeObject(message);
        this.objectOutputStream.flush();
    }

}
