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
    private final String regex = "\\[\\d\\d:\\d\\d:\\d\\d\\]\\t[IE][NR][FR][O][R]*\\t\\X*";
    private final Pattern pattern = Pattern.compile(regex);

    @BeforeEach
    public void setUp() {
        System.setOut(new PrintStream(outputStreamCaptor));
    }

    @Test
    void TestWrite() {
        Logger.info("TEST INFO");
        final Matcher matcher = pattern.matcher(outputStreamCaptor.toString());
        assertTrue(matcher.matches());
    }

    @Test
    void TestError() {
        Logger.info("TEST ERROR");
        final Matcher matcher = pattern.matcher(outputStreamCaptor.toString());
        assertTrue(matcher.matches());
    }

}