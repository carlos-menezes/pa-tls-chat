package server;

import picocli.CommandLine;

import java.io.IOException;

public class Main {
    public static void main(String[] args) throws IOException {
        int exitCode = new CommandLine(new Server()).execute(args);
        System.exit(exitCode);
    }
}