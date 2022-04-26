package config;

import java.io.IOException;
import java.util.Properties;
import java.io.FileInputStream;

/**
 * The <code>Config</code> class represents a persistent set of properties.
 * The properties list in this object originates from a config file.
 * All the values in the properties list can be accessed by its key value using {@link Config#getValue(String)}.
 */
public class Config {

    // Properties from the file
    private Properties properties;

    /**
     * Creates a property object with the values read from a config file.
     *
     * @param fileName pathname of the file
     * @throws ConfigFileNotFoundException if an error occurred when opening or reading the config file
     */
    public Config(String fileName) throws ConfigFileNotFoundException {
        // Created new property list
        this.properties = new Properties();
        try {
            // Tries to open the config file
            FileInputStream fis = new FileInputStream(fileName);
            // Load the data from the file
            this.properties.load(fis);
            fis.close();
        } catch (IOException e) {
            // Throw exception if it couldn't read the file
            throw new ConfigFileNotFoundException("Could not open/read config file");
        }
    }

    /**
     * Searches for the property with the specified key.
     * The method return <code>null</code> if the property was not found
     *
     * @param propertyKey the key of the property
     * @return the value in the property object with the specified key value
     */
    public String getValue(String propertyKey) {
        return properties.getProperty(propertyKey);
    }
}