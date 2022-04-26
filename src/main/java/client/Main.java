package client;

import message.Message;
import picocli.CommandLine;

import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.Socket;

public class Main {
    public static void main(String[] args) throws IOException {
        //int exitCode = new CommandLine(new Client()).execute(args);
        //System.exit(exitCode);
        // need host and port, we want to connect to the ServerSocket at port 7777
        Socket socket = new Socket("localhost", 4000);
        System.out.println("Connected!");

        // get the output stream from the socket.
        OutputStream outputStream = socket.getOutputStream();
        // create an object output stream from the output stream so we can send an object through it
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(outputStream);

        Message message = new Message("testeeeeeeeeee");

        System.out.println("Sending message to the ServerSocket");
        objectOutputStream.writeObject(message);

        System.out.println("Closing socket and terminating program.");
        socket.close();
    }
}
