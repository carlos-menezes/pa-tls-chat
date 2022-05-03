package client;

import client.protocol.Handshake;
import client.util.Generator;
import client.util.Validator;
import picocli.CommandLine;
import shared.encryption.validator.EncryptionAlgorithmType;
import shared.encryption.validator.EncryptionValidator;
import shared.encryption.validator.exceptions.InvalidEncryptionAlgorithmException;
import shared.encryption.validator.exceptions.InvalidKeySizeException;
import shared.hashing.validator.HashingValidator;
import shared.hashing.validator.exceptions.InvalidHashingAlgorithmException;
import shared.keys.schemes.AsymmetricEncryptionScheme;
import shared.message.communication.ServerMessage;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Scanner;
import java.util.concurrent.Callable;

@CommandLine.Command(name = "client", mixinStandardHelpOptions = true, version = "0.1")
public class Client implements Callable<Integer> {
    /**
     * Commands line options
     */
    @CommandLine.Option(names = {"-e",
                                 "--encryption-algorithms"}, description = "Encryption algorithm", required = true)
    @SuppressWarnings("FieldMayBeFinal")
    private String encryptionAlgorithm = "";

    @CommandLine.Option(names = {"-k", "--key-size"}, description = "Key size", required = true)
    @SuppressWarnings("FieldMayBeFinal")
    private Integer keySize = 0;

    @CommandLine.Option(names = {"-m", "--hashing-algorithms"}, description = "Hashing algorithm")
    @SuppressWarnings("FieldMayBeFinal")
    private String hashingAlgorithm = "";

    @CommandLine.Option(names = {"-n", "--name"}, description = "Client name")
    @SuppressWarnings("FieldMayBeFinal")
    private String name = "";

    @CommandLine.Option(names = {"--host"}, description = "Server hostname", required = true)
    private String host;

    @CommandLine.Option(names = {"--port"}, description = "Server port", required = true)
    private int port;


    private Socket socket;
    private EncryptionAlgorithmType encryptionAlgorithmType;

    // DES, 3DES and AES
    // This key is actually the shared private Diffie-Hellman key
    private BigInteger symmetricKey;

    // RSA
    private KeyPair RSAKeys;
    private PublicKey serverRSAKey;

    // Streams
    private ObjectOutputStream objectOutputStream;
    private ObjectInputStream objectInputStream;

    @Override
    public Integer call() throws Exception {
        try {
            EncryptionValidator encryptionValidator = new EncryptionValidator();
            encryptionValidator.validate(this.encryptionAlgorithm, this.keySize);

            this.encryptionAlgorithmType = encryptionValidator.getValidators()
                                                              .get(this.encryptionAlgorithm)
                                                              .getType();
            if (this.encryptionAlgorithmType == EncryptionAlgorithmType.ASYMMETRIC) {
                this.RSAKeys = AsymmetricEncryptionScheme.generateKeys(this.keySize);
            }
        } catch (InvalidEncryptionAlgorithmException | InvalidKeySizeException | NoSuchAlgorithmException e) {
            // TODO: appropriate logging
            e.printStackTrace();
            return CommandLine.ExitCode.SOFTWARE;
        }

        if (!this.hashingAlgorithm.isEmpty()) {
            try {
                HashingValidator hashingValidator = new HashingValidator();
                hashingValidator.validate(this.hashingAlgorithm);
            } catch (InvalidHashingAlgorithmException e) {
                // TODO: appropriate logging
                e.printStackTrace();
                return CommandLine.ExitCode.SOFTWARE;
            }
        }

        if (this.name.isEmpty()) {
            this.name = Generator.generateUsername();
        } else {
            boolean validUsername = Validator.validateUsername(this.name);
            if (!validUsername) {
                // TODO: appropriate logging
                return CommandLine.ExitCode.SOFTWARE;
            }
        }

        // Initialize client's socket
        try {
            this.socket = new Socket(host, port);
            this.objectOutputStream = new ObjectOutputStream(this.socket.getOutputStream());
            this.objectInputStream = new ObjectInputStream(this.socket.getInputStream());
        } catch (IOException e) {
            e.printStackTrace();
        }

        Handshake handshake = new Handshake(this);
        handshake.call();

        while(this.socket.isConnected()) {
            Scanner usrInput = new Scanner( System.in );
            String message = usrInput.nextLine( );
            System.out.println("Message was sent");
            objectOutputStream.writeObject(message);
            objectOutputStream.flush();
        }

        return null;
    }

    private void readMessages() {
        new Thread(() -> {
            while(this.socket.isConnected()) {
                try {
                    ServerMessage serverMessage = (ServerMessage) this.objectInputStream.readObject();
                } catch (IOException | ClassNotFoundException e) {
                    try {
                        closeConnection();
                    } catch (IOException ex) {
                        ex.printStackTrace();
                    }
                }
            }
        });
    }

    private void closeConnection() throws IOException {
        this.socket.close();
        this.objectOutputStream.close();
        this.objectInputStream.close();
    }

    public String getEncryptionAlgorithm() {
        return encryptionAlgorithm;
    }

    public Integer getKeySize() {
        return keySize;
    }

    public String getHashingAlgorithm() {
        return hashingAlgorithm;
    }

    public String getName() {
        return name;
    }

    public Socket getSocket() {
        return socket;
    }

    public EncryptionAlgorithmType getEncryptionAlgorithmType() {
        return encryptionAlgorithmType;
    }

    public BigInteger getSymmetricKey() {
        return symmetricKey;
    }

    public KeyPair getRSAKeys() {
        return RSAKeys;
    }

    public PublicKey getServerRSAKey() {
        return serverRSAKey;
    }

    public ObjectOutputStream getObjectOutputStream() {
        return objectOutputStream;
    }

    public ObjectInputStream getObjectInputStream() {
        return objectInputStream;
    }

    public Client setServerRSAKey(PublicKey serverRSAKey) {
        this.serverRSAKey = serverRSAKey;
        return this;
    }

    public Client setSymmetricKey(BigInteger symmetricKey) {
        this.symmetricKey = symmetricKey;
        return this;
    }
}
