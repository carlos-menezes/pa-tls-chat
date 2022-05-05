package client.util;

import org.junit.jupiter.api.RepeatedTest;

import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertTrue;

class GeneratorTest {
    private final Pattern pattern = Pattern.compile("[A-Z][a-z]+-[A-Z][a-z]+-\\d+");

    @RepeatedTest(5)
    void TestUsernameGenerator() {
        assertTrue(this.pattern.matcher(Generator.generateUsername())
                               .matches());
    }
}