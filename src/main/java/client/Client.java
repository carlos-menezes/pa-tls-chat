package client;

import client.protocol.Handshake;
import client.util.Generator;
import client.util.Validator;
import picocli.CommandLine;
import shared.encryption.codec.Decoder;
import shared.encryption.validator.EncryptionAlgorithmType;
import shared.encryption.validator.EncryptionValidator;
import shared.encryption.validator.exceptions.InvalidEncryptionAlgorithmException;
import shared.encryption.validator.exceptions.InvalidKeySizeException;
import shared.hashing.codec.HashingEncoder;
import shared.hashing.validator.HashingValidator;
import shared.hashing.validator.exceptions.InvalidHashingAlgorithmException;
import shared.hashing.validator.exceptions.UnsupportedHashingAlgorithmException;
import shared.keys.schemes.AsymmetricEncryptionScheme;
import shared.logging.Logger;
import shared.message.communication.ClientMessage;
import shared.message.communication.ServerMessage;
import shared.message.communication.ServerUserStatusMessage;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.*;
import java.util.Scanner;
import java.util.concurrent.Callable;
import java.util.regex.Pattern;

@CommandLine.Command(name = "client", mixinStandardHelpOptions = true, version = "0.1")
public class Client implements Callable<Integer> {
    private static final String INPUT_PROMPT = "> ";
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
    @CommandLine.Option(names = {"-m",
                                 "--hashing-algorithms"}, description = "Hashing algorithm", defaultValue =
            "SHA256withRSA")
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

    // Symmetric encryption key
    private BigInteger symmetricEncryptionKey;

    // Signing
    private KeyPair signingKeys;
    private PublicKey serverSigningKey;

    // RSA
    private KeyPair RSAKeys; // Client's own RSA key pair
    private PublicKey serverRSAKey;

    // Streams
    private ObjectOutputStream objectOutputStream;
    private ObjectInputStream objectInputStream;


    @Override
    public Integer call() throws Exception {
        try {
            EncryptionValidator encryptionValidator = new EncryptionValidator();
            encryptionValidator.validate(this.encryptionAlgorithm, this.keySize);

            this.setSigningKeys(AsymmetricEncryptionScheme.generateKeys(4096));
            this.encryptionAlgorithmType = encryptionValidator.getValidators()
                                                              .get(this.encryptionAlgorithm)
                                                              .getType();
            if (this.encryptionAlgorithmType == EncryptionAlgorithmType.ASYMMETRIC) {
                this.RSAKeys = AsymmetricEncryptionScheme.generateKeys(this.keySize);
            }
        } catch (InvalidEncryptionAlgorithmException | InvalidKeySizeException | NoSuchAlgorithmException e) {
            Logger.error(e.getMessage());
            return CommandLine.ExitCode.SOFTWARE;
        }

        if (!this.hashingAlgorithm.isEmpty()) {
            try {
                HashingValidator hashingValidator = new HashingValidator();
                hashingValidator.validate(this.hashingAlgorithm);
            } catch (InvalidHashingAlgorithmException | UnsupportedHashingAlgorithmException e) {
                Logger.error(e.getMessage());
                return CommandLine.ExitCode.SOFTWARE;
            }
        }

        if (this.name.isEmpty()) {
            this.name = Generator.generateUsername();
        } else {
            boolean validUsername = Validator.validateUsername(this.name);
            if (!validUsername) {
                Logger.error("Invalid username (must not contain ',', '@' or ' ')");
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
        Integer hasError = handshake.call();
        if (hasError == 1) {
            return CommandLine.ExitCode.SOFTWARE;
        }

        Logger.info("Welcome to #pa-tls-chat.");
        this.readMessages();
        this.writeMessages();
        return CommandLine.ExitCode.OK;
    }

    /**
     * Method that creates a thread to handle all the messages received from the server
     */
    private void readMessages() {
        new Thread(() -> {
            while (this.socket.isConnected()) {
                try {
                    Object message = this.objectInputStream.readObject();
                    if (message instanceof ServerMessage serverMessage) {
                        byte[] decodedContent = Decoder.decodeMessage(serverMessage.getMessage(), this);
                        boolean validHash = Decoder.validateSignature(decodedContent, this.getHashingAlgorithm(), this.getServerSigningKey(), serverMessage.getSignature());

                        // Verify if hashes match
                        if (!validHash) {
                            Logger.error("Hashes do not match");
                        }

                        Logger.message(serverMessage.getSender(), new String(decodedContent));
                    } else if (message instanceof ServerUserStatusMessage serverUserStatusMessage) {
                        Logger.info(new String(serverUserStatusMessage.getMessage()));
                    }
                } catch (IOException | ClassNotFoundException e) {
                    e.printStackTrace();
                    try {
                        closeConnection();
                    } catch (IOException ex) {
                        e.printStackTrace();
                    }
                    return;
                } catch (NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | SignatureException e) {
                    e.printStackTrace();
                }
            }
        }).start();
    }

    private void writeMessages() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException, SignatureException {
        while (this.socket.isConnected()) {
            this.displayInputPrompt();
            Scanner input = new Scanner(System.in);
            String message = input.nextLine();
            boolean validMessage = Pattern.matches("^(?!\\s*$).+", message);
            if (!validMessage) {
                Logger.error("Message must not be empty.");
                continue;
            }

            ClientMessage clientMessage = new ClientMessage(message, this);

            try {
                this.objectOutputStream.writeObject(clientMessage);
                this.objectOutputStream.flush();
            } catch (IOException e) {
                e.printStackTrace();
                try {
                    closeConnection();
                    return;
                } catch (IOException ex) {
                    Logger.error(ex.getMessage());
                }
                return;
            }
        }
    }

    private void displayInputPrompt() {
        System.out.print(INPUT_PROMPT);
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

    public String getHost() {
        return host;
    }

    public int getPort() {
        return port;
    }

    public Socket getSocket() {
        return socket;
    }

    public EncryptionAlgorithmType getEncryptionAlgorithmType() {
        return encryptionAlgorithmType;
    }

    public BigInteger getSymmetricEncryptionKey() {
        return symmetricEncryptionKey;
    }

    public void setSymmetricEncryptionKey(BigInteger symmetricEncryptionKey) {
        this.symmetricEncryptionKey = symmetricEncryptionKey;
    }

    public KeyPair getSigningKeys() {
        return signingKeys;
    }


    public PublicKey getServerSigningKey() {
        return serverSigningKey;
    }

    public void setServerSigningKey(PublicKey serverSigningKey) {
        this.serverSigningKey = serverSigningKey;
    }

    public KeyPair getRSAKeys() {
        return RSAKeys;
    }

    public void setRSAKeys(KeyPair RSAKeys) {
        this.RSAKeys = RSAKeys;
    }

    public PublicKey getServerRSAKey() {
        return serverRSAKey;
    }

    public void setServerRSAKey(PublicKey serverRSAKey) {
        this.serverRSAKey = serverRSAKey;
    }

    public ObjectOutputStream getObjectOutputStream() {
        return objectOutputStream;
    }

    public ObjectInputStream getObjectInputStream() {
        return objectInputStream;
    }

    public void setSigningKeys(KeyPair signingKeys) {
        this.signingKeys = signingKeys;
    }
}
