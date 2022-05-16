![image](https://user-images.githubusercontent.com/36506580/168392266-fb109aeb-5802-420b-99c3-14b430ea5ee0.png)

`pa-tls-chat` is a Java implementation of a client-side encrypted chat. The primary objective of this project for the [Advanced Programming](https://www.uma.pt/en/ensino/1o-ciclo/licenciatura-em-engenharia-informatica/15914/?contentid=15914) is to have all the communication mediated by the server. Thus, the server is responsible for decrypting incoming messages from a client and encrypting outgoing messages to a client.

# *Handshake*

## Client
The client builds a `CLIENT_HELLO` message (see: [`ClientHello`](src/main/java/shared/message/handshake/ClientHello.java)) which contains a record of the client's capabilities, such as the {encryption | hashing} algorithm to be used, the key size and the client's name.
The message's content will vary depending on the type of encryption algorithm used:
  - **Symmetric**:
    - Diffie-Hellman keys are generated in order to establish a shared secret between the two communicating parties.
    - The public Diffie-Hellman key is sent to the server.
  - **Asymmetric**:
    - The public RSA key of the client is sent to the server.
  - In both cases, a public 4096-bit RSA key for signing purposes is sent in this message;
- The server waits for one of two messages:
  - `SERVER_ERROR`: terminates the process;
  - `SERVER_HELLO`: saves the incoming data in appropriate attributes.

## Server 
The server must validate the client's username, as usernames are per-client exclusive. If an user with the username contained in `CLIENT_HELLO` already exists, the server replies with a `SERVER_ERROR` message (see: [`ServerError`](src/main/java/shared/message/handshake/ServerError.java)).
Otherwise, that client is added to a list of active users and a [`ClientSpec`](src/main/java/server/client/ClientSpec.java) is created for that user. A `ClientSpec` object contains the specific characteristics of a client, such as the {encryption|hashing} algorithm used, the key sizes, the name, the socket and the signing keys.
The server takes further steps depending on the type of encryption algorithm used:
  - **Symmetric**:
    -  Diffie-Hellman keys are generated in order to establish a shared secret between the two communicating parties.
    -  The shared private key is computed via the Diffie-Hellman key in the incoming `CLIENT_HELLO` message;
  - **Asymmetric**:
    - A RSA key pair with the matching key size is generated;
    - The client's public RSA key is saved.
The server will then send a `SERVER_HELLO` message (see: [`ServerHello`](src/main/java/shared/message/handshake/ServerHello.java)) which sends the client information such as the server's signing keys, the public RSA key (if RSA is used for encryption purposes) and the signing keys. A joining message will be broadcasted to every connected client.

# Configuration

### Client
- `-e, --encryption-algorithms`
- `-k, --key-size`
- `-m, --hashing-algorithm`
- `-n, --name` - Username
- `--host` - Server's IP
- `-p, --port` - Server's port

### Servidor
- `-p, --port` - The port to the run the server on
