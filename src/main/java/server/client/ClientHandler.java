package server.client;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;

public class ClientHandler implements Runnable {
    private final Socket socket;
    private final ObjectInputStream objectInputStream;
    private final ObjectOutputStream objectOutputStream;

    public ClientHandler(Socket socket) throws IOException {
        this.socket = socket;
        this.objectInputStream = new ObjectInputStream(this.socket.getInputStream());
        this.objectOutputStream = new ObjectOutputStream(this.socket.getOutputStream());
    }

    @Override
    public void run() {
        try {
            Object message = this.objectInputStream.readObject();
            System.out.println(message.toString());
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
    }
}
