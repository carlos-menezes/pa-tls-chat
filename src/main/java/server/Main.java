package server;

import config.Config;
import config.ConfigFileNotFoundException;

import java.io.IOException;

public class Main {
    /**
     * Main class of the program, where the config and server are started
     *
     * @param args Program arguments
     */
    public static void main(String[] args) {
        try {
            Config config = new Config("./server.config");
            Server server = new Server(config);
            server.run();
        } catch (ConfigFileNotFoundException | InterruptedException | IOException e) {
            e.printStackTrace();
        }
    }

}
