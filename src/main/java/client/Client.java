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
import shared.keys.schemes.SymmetricEncryptionScheme;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.net.Socket;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.Callable;

@CommandLine.Command(name = "client", mixinStandardHelpOptions = true, version = "0.1")
public class Client implements Callable<Integer> {
    /**
     * Commands line options
     */
    @CommandLine.Option(names = {"-e", "--encryption-algorithms"}, description = "Encryption algorithm", required = true)
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

    /**
     * Class attributes.
     */
    private Socket socket;
    private EncryptionAlgorithmType encryptionAlgorithmType;
    private SecretKey symmetricKey;
    private KeyPair asymmetricKey;

    @Override
    public Integer call() throws Exception {
        try {
            EncryptionValidator encryptionValidator = new EncryptionValidator();
            encryptionValidator.validate(this.encryptionAlgorithm, this.keySize);

            EncryptionAlgorithmType encryptionAlgorithmType = encryptionValidator.getValidators()
                                                                                 .get(this.encryptionAlgorithm)
                                                                                 .getType();
            switch (encryptionAlgorithmType) {
                case SYMMETRIC -> this.symmetricKey = SymmetricEncryptionScheme.generateKey(this.encryptionAlgorithm,
                                                                                            this.keySize);
                case ASYMMETRIC -> this.asymmetricKey = AsymmetricEncryptionScheme.generateKeys(
                        this.encryptionAlgorithm, this.keySize);
            }
        } catch (InvalidEncryptionAlgorithmException | InvalidKeySizeException | NoSuchAlgorithmException e) {
            // TODO: appropriate logging
            e.printStackTrace();
            return CommandLine.ExitCode.SOFTWARE;
        }

        try {
            HashingValidator hashingValidator = new HashingValidator();
            hashingValidator.validate(this.hashingAlgorithm);
        } catch (InvalidHashingAlgorithmException e) {
            // TODO: appropriate logging
            e.printStackTrace();
            return CommandLine.ExitCode.SOFTWARE;
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
        } catch (IOException e) {
            e.printStackTrace();
        }

        Handshake handshake = new Handshake(this);
        handshake.call();
        return null;
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

    public SecretKey getSymmetricKey() {
        return symmetricKey;
    }

    public KeyPair getAsymmetricKey() {
        return asymmetricKey;
    }
}
