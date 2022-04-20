package client;

import picocli.CommandLine;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;

@CommandLine.Command(name = "client", mixinStandardHelpOptions = true, version = "0.1")
class Client implements Callable<Integer> {
    @CommandLine.Option(names = {"-e", "--encryption-algorithms"}, split = ",", description = "Supported encryption algorithms: DES, 3DES, AES, RSA", required = true)
    private List<String> supportedEncryptionAlgorithms = new ArrayList<>();

    @CommandLine.Option(names = {"-m", "--mangling-algorithms"}, split = ",", description = "Supported hashing/mangling algorithms: MD4, MD5, SHA-256, SHA-512", required = true)
    private List<String> supportedHashingAlgorithms = new ArrayList<>();

    @CommandLine.Option(names = {"-k", "--key-sizes"}, split = ",", description = "Supported key sizes: DES (64), 3DES (192), AES (128 | 192 | 256), RSA (1024 | 2048 | 4096)", required = true)
    private List<Integer> supportedKeySizes = new ArrayList<>();

    @Override
    public Integer call() throws Exception {
        System.out.println(this.supportedEncryptionAlgorithms);
        System.out.println(this.supportedKeySizes);
        System.out.println(this.supportedHashingAlgorithms);
        return null;
    }
}
