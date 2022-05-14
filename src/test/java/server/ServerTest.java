package server;

import org.junit.jupiter.api.Test;
import picocli.CommandLine;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ServerTest {
    @Test
    void testRun() {
        String[] args = "--port 9504".split(" ");
        Server server = new Server();
        new CommandLine(server).parseArgs(args);
        assertEquals(server.getPort(), 9504);
    }
}