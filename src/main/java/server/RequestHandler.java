package server;

import message.Message;

import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;

/**
 * The <code>RequestHandler</code> class represents a handler to handle
 * the requests.
 * Implements the interface {@link Runnable}.
 */
public class RequestHandler implements Runnable {

    private final RequestHandlerParameters parameters;

    /**
     * Creates a new <code>RequestHandler</code> object by specifying the request parameters.
     *
     * @param parameters request parameters
     */
    public RequestHandler(RequestHandlerParameters parameters) {
        this.parameters = parameters;
    }

    /**
     * Method that handles the connection so that requests can be made.
     *
     * @throws IOException when there is a problem with the input/output streams
     */
    private void handleConnection() throws IOException, ClassNotFoundException {
        InputStream inputStream = this.parameters.getSocket().getInputStream();
        ObjectInputStream objectInputStream = new ObjectInputStream(inputStream);

        // Throws exception if the cast is not successful
        Message receivedMessage = (Message) objectInputStream.readObject();

        System.out.print(receivedMessage.getTeste());

        OutputStream outputStream = this.parameters.getSocket().getOutputStream();

        //Message messageResponse = new Message();

        //outputStream.write(messageResponse);
        outputStream.flush();
        this.parameters.getSocket().close();
        String remoteAddress = ((InetSocketAddress) this.parameters.getSocket().getRemoteSocketAddress()).getAddress()
                .toString();
    }

    @Override
    public void run() {
        try {
            handleConnection();
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
    }

}