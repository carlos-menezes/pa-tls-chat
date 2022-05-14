package client.util;

import com.github.javafaker.Faker;

/**
 * {@link Generator} is an utility class which generates fake data on demand.
 */
public class Generator {
    private static final Faker faker = new Faker();

    /**
     * Generates a <b>valid</b> username.
     * @return a valid username string
     */
    public static String generateUsername() {
        return faker.superhero().prefix() + "-" + faker.name().firstName() + "-" + faker.address().buildingNumber();
    }
}
