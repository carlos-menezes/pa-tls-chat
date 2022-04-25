package client;

import picocli.CommandLine;
import shared.encryption.validator.EncryptionValidator;
import shared.encryption.validator.exceptions.InvalidEncryptionAlgorithmException;
import shared.encryption.validator.exceptions.InvalidKeySizeException;
import shared.hashing.validator.HashingValidator;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;

@CommandLine.Command(name = "client", mixinStandardHelpOptions = true, version = "0.1")
class Client implements Callable<Integer> {
    @CommandLine.Option(names = {"-e", "--encryption-algorithms"}, split = ",", description = "Supported encryption algorithms: DES, 3DES, AES, RSA", required = true)
    private List<String> supportedEncryptionAlgorithms = new ArrayList<>();

    @CommandLine.Option(names = {"-k", "--key-sizes"}, split = ",", description = "Supported key sizes: DES (64), 3DES (192), AES (128 | 192 | 256), RSA (1024 | 2048 | 4096)", required = true)
    private List<Integer> supportedKeySizes = new ArrayList<>();

    @CommandLine.Option(names = {"-m", "--hashing-algorithms"}, split = ",", description = "Supported hashing algorithms: MD4, MD5, SHA-256, SHA-512", required = true)
    private List<String> supportedHashingAlgorithms = new ArrayList<>();

    @CommandLine.Option(names = { "-n", "--name"}, description = "Client identification string (spaces aren't allowed)")
    private String name = "";

    @Override
    public Integer call() throws Exception {
        EncryptionValidator encryptionValidator = new EncryptionValidator(this.supportedEncryptionAlgorithms, this.supportedKeySizes);
        HashingValidator hashingValidator = new HashingValidator(this.supportedHashingAlgorithms);

        try {
            encryptionValidator.validate();
            hashingValidator.validate();
        } catch (InvalidEncryptionAlgorithmException | InvalidKeySizeException e) {
            // TODO: appropriate logging
            e.printStackTrace();

            return CommandLine.ExitCode.SOFTWARE;
        }

        System.out.println(this.supportedHashingAlgorithms);
        System.out.println(this.name);
        return null;
    }
}
