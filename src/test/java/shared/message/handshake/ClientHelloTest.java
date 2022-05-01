package shared.message.handshake;

import client.Client;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import picocli.CommandLine;
import shared.message.handshake.client.ClientHello;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ClientHelloTest {
    private ClientHello clientHello;

    @BeforeEach
    void setUp() {
        String[] args = "-e AES -k 256 -m SHA-256 -n pa-user --host localhost --port 1337".split(" ");
        Client client = new Client();
        new CommandLine(client).parseArgs(args);
        this.clientHello = new ClientHello(client);
    }

    @Test
    void TestClientHello() {
        assertEquals(this.clientHello.getName(), "pa-user");
        assertEquals(this.clientHello.getEncryptionAlgorithm(), "AES");
        assertEquals(this.clientHello.getKeySize(), 256);
        assertEquals(this.clientHello.getHashingAlgorithm(), "SHA-256");
    }
}