package client.util;

import java.util.regex.Pattern;

/**
 * {@link Validator} is an utility class which checks if the supplied username is valid or not.
 */
public class Validator {
    /**
     * Validates whether a given <code>name</code> is valid (i.e. doesn't contain disallowed characters).
     * @param name name to check
     * @return true if name is valid; false otherwise
     */
    public static boolean validateUsername(String name) {
        Pattern pattern = Pattern.compile("[,@\\s]");
        boolean nameContainsSpecialCharacters = pattern.matcher(name).find();
        return !nameContainsSpecialCharacters;
    }
}
