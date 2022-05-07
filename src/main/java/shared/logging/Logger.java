package shared.logging;

import shared.message.communication.ServerMessage;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class Logger {
    private static final DateTimeFormatter dateTimeFormatter = DateTimeFormatter.ofPattern("HH:mm:ss");

    private enum METHOD {
        INFO,
        ERROR
    }

    private static void write(String method, String message) {
        LocalDateTime now = LocalDateTime.now();
        String formattedOutput = "";
        formattedOutput += String.format("[%s]\t", dateTimeFormatter.format(now));
        formattedOutput += String.format("[%s]\t", method);
        formattedOutput += message;
        System.out.println(formattedOutput);
    }

    public static void info(String message) {
        write(String.valueOf(METHOD.INFO), message);
    }

    public static void error(String message) {
        write(String.valueOf(METHOD.ERROR), message);
    }

    public static void message(ServerMessage serverMessage) { write(serverMessage.getSender(), serverMessage.getMessage()); }
}
