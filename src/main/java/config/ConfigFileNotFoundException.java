package config;

/**
 * Signals that an attempt to open a config file denoted by a specific pathname has failed.
 * The class <code>ConfigFileNotFoundException</code> is a subclass of {@link Exception} and
 * will be thrown by {@link Config}.
 */
public class ConfigFileNotFoundException extends Exception {
    /**
     * Constructs a <code>ConfigFileNotFoundException</code> with a specified detail message.
     * The string <code>errorMessage</code> can be retrieved later by the {@link Throwable#getMessage()}
     * method of class <code>java.lang.Throwable</code>.
     *
     * @param errorMessage the detail message
     */
    public ConfigFileNotFoundException(String errorMessage) {
        super(errorMessage);
    }

}