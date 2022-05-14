package shared.logging;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertTrue;

class LoggerTest {
    private final ByteArrayOutputStream outputStreamCaptor = new ByteArrayOutputStream();
    private final String regex = "\\[\\d\\d:\\d\\d:\\d\\d]\\t\\[\\X*]\\t\\X*";
    private final Pattern pattern = Pattern.compile(regex);

    @BeforeEach
    public void setUp() {
        System.setOut(new PrintStream(outputStreamCaptor));
    }

    @Test
    void TestInfo() {
        Logger.info("TEST INFO");
        final Matcher matcher = pattern.matcher(outputStreamCaptor.toString());
        assertTrue(matcher.matches());
    }

    @Test
    void TestError() {
        Logger.error("TEST ERROR");
        final Matcher matcher = pattern.matcher(outputStreamCaptor.toString());
        assertTrue(matcher.matches());
    }

    @Test
    void TestMessage() {
        Logger.message("pa-user", "Hello World");
        final Matcher matcher = pattern.matcher(outputStreamCaptor.toString());
        assertTrue(matcher.matches());
    }

}