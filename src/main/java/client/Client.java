package client;

import client.protocol.Handshake;
import client.util.Generator;
import client.util.Validator;
import org.apache.commons.lang3.SerializationUtils;
import picocli.CommandLine;
import shared.encryption.validator.EncryptionAlgorithmType;
import shared.encryption.validator.EncryptionValidator;
import shared.encryption.validator.exceptions.InvalidEncryptionAlgorithmException;
import shared.encryption.validator.exceptions.InvalidKeySizeException;
import shared.hashing.validator.HashingValidator;
import shared.hashing.validator.exceptions.InvalidHashingAlgorithmException;
import shared.hashing.validator.exceptions.UnsupportedHashingAlgorithmException;
import shared.keys.schemes.AsymmetricEncryptionScheme;
import shared.keys.schemes.SymmetricEncryptionScheme;
import shared.logging.Logger;
import shared.message.communication.ClientMessage;
import shared.message.communication.ServerMessage;
import shared.message.communication.ServerUserStatusMessage;
import shared.message.communication.SignedMessage;
import shared.signing.MessageSigner;
import shared.signing.MessageValidator;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.*;
import java.util.Base64;
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
    private KeyPair SigningKeys;
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
            this.SigningKeys = AsymmetricEncryptionScheme.generateKeys(4096);
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
                            case SYMMETRIC -> {
                                byte[] sharedKeyBytes = this.getEncryptionKey().toByteArray();
                                byte[] bytes = ByteBuffer.allocate(this.getKeySize() / 8).put(sharedKeyBytes).array();
                                SecretKeySpec secretKey = new SecretKeySpec(bytes, this.getEncryptionAlgorithm());
                                serverMessage = SerializationUtils.deserialize(signedMessage.getEncryptedMessageBytes());
                                byte[] encryptedMessageBytes = Base64.getDecoder().decode(serverMessage.getMessage());
                                Cipher decryptCipher = Cipher.getInstance(this.getEncryptionAlgorithm());
                                decryptCipher.init(Cipher.DECRYPT_MODE, secretKey);
                                byte[] decryptedMessageBytes = decryptCipher.doFinal(encryptedMessageBytes);
                                serverMessage.setMessage(new String(decryptedMessageBytes));


                            }
                            case ASYMMETRIC -> {
                                serverMessage = SerializationUtils.deserialize(signedMessage.getEncryptedMessageBytes());
                                byte[] encryptedMessageBytes = Base64.getDecoder().decode(serverMessage.getMessage());
                                Cipher decryptCipher = Cipher.getInstance("RSA");
                                decryptCipher.init(Cipher.DECRYPT_MODE, this.serverRSAKey);
                                byte[] decryptedMessageBytes = decryptCipher.doFinal(encryptedMessageBytes);
                                serverMessage.setMessage(new String(decryptedMessageBytes));
                                System.out.println("assimetrico");
                            }
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
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                } catch (SignatureException e) {
                    e.printStackTrace();
                } catch (InvalidKeyException e) {
                    e.printStackTrace();
                } catch (NoSuchPaddingException e) {
                    e.printStackTrace();
                } catch (IllegalBlockSizeException e) {
                    e.printStackTrace();
                } catch (BadPaddingException e) {
                    e.printStackTrace();
                }
            }
        }).start();
    }

    private void writeMessages() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
            IllegalBlockSizeException, IOException, BadPaddingException, SignatureException {
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

            // Encrypt message
            SignedMessage signedMessage = null;
            switch (this.encryptionAlgorithmType) {
                // Encrypts the entire ClientMessage object
                case SYMMETRIC -> {
                    byte[] sharedKeyBytes = this.getEncryptionKey().toByteArray();
                    byte[] bytes = ByteBuffer.allocate(this.getKeySize() / 8).put(sharedKeyBytes).array();
                    SecretKeySpec secretKey = new SecretKeySpec(bytes, this.encryptionAlgorithm);
                    Cipher cipher = Cipher.getInstance(this.encryptionAlgorithm);
                    cipher.init(Cipher.ENCRYPT_MODE, secretKey);

                    byte[] encryptedClientMessageBytes = cipher.doFinal(clientMessage.getMessage().getBytes());
                    clientMessage.setMessage(Base64.getEncoder().encodeToString(encryptedClientMessageBytes));

                    byte[] clientMessageBytes = SerializationUtils.serialize(clientMessage);
                    signedMessage = MessageSigner.signMessage(this.hashingAlgorithm, this.getSigningKeys().getPrivate(), clientMessageBytes);
                }
                // Encrypts only the message property of ClientMessage (due to RSA constraints)
                case ASYMMETRIC -> {
                    Cipher cipher = Cipher.getInstance(this.encryptionAlgorithm);
                    cipher.init(Cipher.ENCRYPT_MODE, this.serverRSAKey);
                    byte[] encryptedClientMessageBytes = cipher.doFinal(clientMessage.getMessage().getBytes());
                    clientMessage.setMessage(Base64.getEncoder().encodeToString(encryptedClientMessageBytes));

                    byte[] clientMessageBytes = SerializationUtils.serialize(clientMessage);
                    signedMessage = MessageSigner.signMessage(this.hashingAlgorithm, this.getSigningKeys().getPrivate(), clientMessageBytes);
                }
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

    public Socket getSocket() {
        return socket;
    }

    public EncryptionAlgorithmType getEncryptionAlgorithmType() {
        return encryptionAlgorithmType;
    }

    public BigInteger getEncryptionKey() {
        return encryptionKey;
    }

    public void setEncryptionKey(BigInteger encryptionKey) {
        this.encryptionKey = encryptionKey;
    }

    public KeyPair getSigningKeys() {
        return SigningKeys;
    }

    public KeyPair getRSAKeys() {
        return RSAKeys;
    }

    public PublicKey getServerRSAKey() {
        return serverRSAKey;
    }

    public void setServerRSAKey(PublicKey serverRSAKey) {
        this.serverRSAKey = serverRSAKey;
    }

    public PublicKey getServerSigningKey() {
        return serverRSAKey;
    }

    public void setServerSigningKey(PublicKey serverSigningKey) {
        this.serverSigningKey = serverSigningKey;
    }

    public ObjectOutputStream getObjectOutputStream() {
        return objectOutputStream;
    }

    public ObjectInputStream getObjectInputStream() {
        return objectInputStream;
    }
}
