package shared.logging;

import shared.message.communication.ServerMessage;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * The <code>Logger</code> class represents the logging operations
 */
public class Logger {
    private static final DateTimeFormatter dateTimeFormatter = DateTimeFormatter.ofPattern("HH:mm:ss");

    /**
     * Logger methods
     */
    private enum METHOD {
        INFO,
        ERROR
    }

    /**
     * Method to write information on the terminal
     *
     * @param method Logger method
     * @param message Message to be displayed
     */
    private static void write(String method, String message) {
        LocalDateTime now = LocalDateTime.now();
        String formattedOutput = "";
        formattedOutput += String.format("[%s]\t", dateTimeFormatter.format(now));
        formattedOutput += String.format("[%s]\t", method);
        formattedOutput += message;
        System.out.println(formattedOutput);
    }

    /**
     * Method that writes a message of the <code>Info</code> type on the terminal.
     *
     * @param message Message to be displayed
     */
    public static void info(String message) {
        write(String.valueOf(METHOD.INFO), message);
    }

    /**
     * Method that writes a message of the <code>Error</code> type on the terminal.
     *
     * @param message Message to be displayed
     */
    public static void error(String message) {
        write(String.valueOf(METHOD.ERROR), message);
    }

    /**
     * Method that writes a simple message on the terminal
     *
     * @param serverMessage Message from the server
     */
    public static void message(ServerMessage serverMessage) { write(serverMessage.getSender(), serverMessage.getMessage()); }
}
