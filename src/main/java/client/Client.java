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

            // Gera o par RSA para assinatura
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

        System.out.println(this.getEncryptionKey());

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
                    if (message instanceof SealedObject sealedObject) {
                        ServerMessage serverMessage = null;
                        switch (this.getEncryptionAlgorithmType()) {
                            case SYMMETRIC -> {
                                SecretKeySpec secretKeySpec = SymmetricEncryptionScheme.getSecretKeyFromBytes(
                                        this.getKeySize(),
                                        this.encryptionKey.toByteArray(),
                                        this.getEncryptionAlgorithm());
                                serverMessage = (ServerMessage) sealedObject.getObject(secretKeySpec);
                            }
                            case ASYMMETRIC -> {
                                SecretKeySpec secretKeySpec = SymmetricEncryptionScheme.getSecretKeyFromBytes(
                                        256,
                                        this.encryptionKey.toByteArray(),
                                        "AES");
                                serverMessage = (ServerMessage) sealedObject.getObject(secretKeySpec);
                            }
                        }
                        Logger.message(serverMessage);
                    } else {
                        if (message instanceof ServerUserStatusMessage serverUserStatusMessage) {
                            Logger.info(serverUserStatusMessage.getMessage());
                        }
                    }
                } catch (IOException | ClassNotFoundException | NoSuchAlgorithmException | InvalidKeyException e) {
                    try {
                        closeConnection();
                    } catch (IOException ex) {
                        Logger.error(ex.getMessage());
                    }
                    return;
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
            SealedObject sealedObject;
            SignedMessage signedMessage = null;
            switch (this.encryptionAlgorithmType) {
                case SYMMETRIC -> {
                    // Encripta com o algoritmo escolhido (ex: DES)
                    byte[] sharedKeyBytes = this.getEncryptionKey().toByteArray();
                    byte[] bytes = ByteBuffer.allocate(  this.getKeySize() / 8 ).put( sharedKeyBytes ).array( );
                    SecretKeySpec secretKey = new SecretKeySpec( bytes , this.encryptionAlgorithm.equals("3DES") ? "TripleDES" : this.encryptionAlgorithm);
                    Cipher cipher = Cipher.getInstance(this.encryptionAlgorithm.equals("3DES") ? "TripleDES" : this.encryptionAlgorithm);
                    cipher.init( Cipher.ENCRYPT_MODE , secretKey );
                    sealedObject = new SealedObject(clientMessage, cipher);

                    byte[] sealedObjectBytes = SerializationUtils.serialize(sealedObject);

                    // Assina o objeto encriptado com o algoritmo de hash preferido, usa o SHA256 como fallback
                    Signature signature = Signature.getInstance(this.hashingAlgorithm.isEmpty() ? "SHA256withRSA": this.hashingAlgorithm);
                    signature.initSign(this.getSigningKeys().getPrivate());
                    signature.update(sealedObjectBytes);
                    byte[] digitalSignature = signature.sign();
                    signedMessage = new SignedMessage(sealedObjectBytes,digitalSignature);
                }
                case ASYMMETRIC -> {
                    // Encripta com o RSA (apenas a mensagem)
                    Cipher cipher = Cipher.getInstance(this.encryptionAlgorithm);
                    cipher.init( Cipher.ENCRYPT_MODE , this.serverRSAKey );
                    byte[] clientMessageBytes = clientMessage.getMessage().getBytes();
                    byte[] encryptedClientMessageBytes = cipher.doFinal(clientMessageBytes);
                    clientMessage.setMessage(Base64.getEncoder().encodeToString(encryptedClientMessageBytes));

                    byte[] sealedObjectBytes = SerializationUtils.serialize(clientMessage);

                    // Assina o objeto encriptado com o algoritmo de hash preferido, usa o SHA256 como fallback
                    Signature signature = Signature.getInstance(this.hashingAlgorithm.isEmpty() ? "SHA256withRSA": this.hashingAlgorithm);
                    signature.initSign(this.getSigningKeys().getPrivate());
                    signature.update(sealedObjectBytes);
                    byte[] digitalSignature = signature.sign();
                    signedMessage = new SignedMessage(sealedObjectBytes,digitalSignature);
                }
                default -> throw new IllegalStateException("Unexpected value: " + this.encryptionAlgorithmType);
            }

            try {
                this.objectOutputStream.writeObject(signedMessage);
                this.objectOutputStream.flush();
            } catch (IOException e) {
                try {
                    System.out.println(e);
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

    public ObjectOutputStream getObjectOutputStream() {
        return objectOutputStream;
    }

    public ObjectInputStream getObjectInputStream() {
        return objectInputStream;
    }
}
