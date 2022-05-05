package shared.logging;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class Logger {
    private static final DateTimeFormatter dateTimeFormatter = DateTimeFormatter.ofPattern("HH:mm:ss");

    private enum METHOD {
        INFO,
        ERROR
    }

    private static void write(METHOD method, String message) {
        LocalDateTime now = LocalDateTime.now();
        String formattedOutput = "";
        formattedOutput += String.format("[%s]\t", dateTimeFormatter.format(now));
        formattedOutput += String.format("%s\t", method.toString());
        formattedOutput += message;
        System.out.println(formattedOutput);
    }

    public static void info(String message) {
        write(METHOD.INFO, message);
    }

    public static void error(String message) {
        write(METHOD.ERROR, message);
    }
}
