package client;

import client.protocol.Handshake;
import client.util.Generator;
import client.util.Validator;
import picocli.CommandLine;
import shared.encryption.decoder.MessageDecoder;
import shared.encryption.encoder.MessageEncoder;
import shared.encryption.validator.EncryptionAlgorithmType;
import shared.encryption.validator.EncryptionValidator;
import shared.encryption.validator.exceptions.InvalidEncryptionAlgorithmException;
import shared.encryption.validator.exceptions.InvalidKeySizeException;
import shared.hashing.validator.HashingValidator;
import shared.hashing.validator.exceptions.InvalidHashingAlgorithmException;
import shared.hashing.validator.exceptions.UnsupportedHashingAlgorithmException;
import shared.keys.schemes.AsymmetricEncryptionScheme;
import shared.logging.Logger;
import shared.message.communication.ClientMessage;
import shared.message.communication.ServerMessage;
import shared.message.communication.ServerUserStatusMessage;
import shared.message.communication.SignedMessage;
import shared.signing.MessageValidator;

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

/**
 * The <code>Client</code> class represents a client that enters the chat to communicate with others
 */
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

    private BigInteger encryptionKey;

    // Signing
    private KeyPair signingKeys;
    private PublicKey serverSigningKey;

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

            // Generates Asymmetric KeyPair for signing purposes
            this.signingKeys = AsymmetricEncryptionScheme.generateKeys(4096);
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
                    if (message instanceof SignedMessage signedMessage) {
                        boolean validSignature = MessageValidator.validateMessage(this.getHashingAlgorithm(), this.serverSigningKey, signedMessage);
                        if (!validSignature) {
                            continue;
                        }

                        ServerMessage serverMessage = null;
                        switch (this.encryptionAlgorithmType) {
                            case SYMMETRIC -> serverMessage = (ServerMessage) MessageDecoder.decodeMessage(signedMessage, this.getEncryptionKey(), this.getKeySize(), this.getEncryptionAlgorithm());
                            case ASYMMETRIC -> serverMessage = (ServerMessage) MessageDecoder.decodeMessage(signedMessage, this.serverRSAKey, this.getEncryptionAlgorithm());
                            default -> throw new IllegalStateException("Unexpected value: " + this.encryptionAlgorithmType);
                        }
                        Logger.message(serverMessage);
                    } else {
                        if (message instanceof ServerUserStatusMessage serverUserStatusMessage) {
                            Logger.info(serverUserStatusMessage.getMessage());
                        }
                    }
                } catch (IOException | ClassNotFoundException e) {
                    try {
                        closeConnection();
                    } catch (IOException ex) {
                        Logger.error(ex.getMessage());
                    }
                    return;
                } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException e) {
                    e.printStackTrace();
                }
            }
        }).start();
    }

    /**
     * Method that sends messages to the server
     */
    private void writeMessages() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException, SignatureException {
        while (this.socket.isConnected()) {
            this.displayInputPrompt();
            Scanner input = new Scanner(System.in);
            String message = input.nextLine();
            ClientMessage clientMessage = new ClientMessage(message);

            boolean validMessage = Pattern.matches("^(?!\\s*$).+", clientMessage.getMessage());
            if (!validMessage) {
                Logger.error("Message must not be empty.");
                continue;
            }

            SignedMessage signedMessage = null;
            // Encrypt message
            switch (this.encryptionAlgorithmType) {
                case SYMMETRIC -> signedMessage = MessageEncoder.encodeMessage(clientMessage, this.encryptionAlgorithm, this.getEncryptionKey(), this.getKeySize(), this.hashingAlgorithm, this.getSigningKeys().getPrivate());
                case ASYMMETRIC -> signedMessage = MessageEncoder.encodeMessage(clientMessage, this.encryptionAlgorithm, this.serverRSAKey, this.hashingAlgorithm, this.signingKeys.getPrivate());
                default -> throw new IllegalStateException("Unexpected value: " + this.encryptionAlgorithmType);
            }

            try {
                this.objectOutputStream.writeObject(signedMessage);
                this.objectOutputStream.flush();
            } catch (IOException e) {
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

    /**
     * Prints the input prompt
     */
    private void displayInputPrompt() {
        System.out.print(INPUT_PROMPT);
    }

    /**
     * Closes the socket connection
     */
    private void closeConnection() throws IOException {
        this.socket.close();
        this.objectOutputStream.close();
        this.objectInputStream.close();
    }

    /**
     * Method that returns the encryption algorithm used by the client
     *
     * @return Clients encryption algorithm
     */
    public String getEncryptionAlgorithm() {
        return encryptionAlgorithm;
    }

    /**
     * Method that returns the clients encryption key size
     *
     * @return Clients encryption key size
     */
    public Integer getKeySize() {
        return keySize;
    }

    /**
     * Method that returns the clients hashing algorithm
     *
     * @return Clients hashing algorithm
     */
    public String getHashingAlgorithm() {
        return hashingAlgorithm;
    }

    /**
     * Method that returns the clients name
     *
     * @return Clients name
     */
    public String getName() {
        return name;
    }

    /**
     * Method that returns the clients socket
     *
     * @return Clients socket
     */
    public Socket getSocket() {
        return socket;
    }

    /**
     * Method that returns the clients encryption type
     *
     * @return Clients encryption type
     */
    public EncryptionAlgorithmType getEncryptionAlgorithmType() {
        return encryptionAlgorithmType;
    }

    /**
     * Method that returns the clients encryption key
     *
     * @return Clients encryption key
     */
    public BigInteger getEncryptionKey() {
        return encryptionKey;
    }

    /**
     * Method that sets the clients encryption key
     *
     * @param encryptionKey Clients encryption key
     */
    public void setEncryptionKey(BigInteger encryptionKey) {
        this.encryptionKey = encryptionKey;
    }

    /**
     * Method that returns the clients signing keys
     *
     * @return Clients signing keys
     */
    public KeyPair getSigningKeys() {
        return signingKeys;
    }

    /**
     * Method that returns the clients RSA keys
     *
     * @return Clients RSA keys
     */
    public KeyPair getRSAKeys() {
        return RSAKeys;
    }

    /**
     * Method that returns the server RSA key
     *
     * @return Server RSA key
     */
    public PublicKey getServerRSAKey() {
        return serverRSAKey;
    }

    /**
     * Method that sets the server RSA key
     * @param serverRSAKey
     */
    public void setServerRSAKey(PublicKey serverRSAKey) {
        this.serverRSAKey = serverRSAKey;
    }

    /**
     * Method that returns the server signing key
     *
     * @return Server signing key
     */
    public PublicKey getServerSigningKey() {
        return serverRSAKey;
    }

    /**
     * Method that sets the server signing key
     *
     * @param serverSigningKey Server signing key
     */
    public void setServerSigningKey(PublicKey serverSigningKey) {
        this.serverSigningKey = serverSigningKey;
    }

    /**
     * Method that returns the object output stream of the connection to the client
     *
     * @return Object output stream of the connection to the client
     */
    public ObjectOutputStream getObjectOutputStream() {
        return objectOutputStream;
    }

    /**
     * Method that returns the object input stream of the connection to the client
     *
     * @return Object input stream of the connection to the client
     */
    public ObjectInputStream getObjectInputStream() {
        return objectInputStream;
    }
}
