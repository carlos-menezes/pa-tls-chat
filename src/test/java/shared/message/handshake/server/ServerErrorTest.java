package shared.message.handshake.server;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ServerErrorTest {
    @Test
    void TestServerError() {
        ServerError serverError = new ServerError("Something bad happened");
        assertEquals(serverError.message(), "Something bad happened");
    }
}