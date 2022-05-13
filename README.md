![image](https://user-images.githubusercontent.com/36506580/168392266-fb109aeb-5802-420b-99c3-14b430ea5ee0.png)

## *Handshake*

- (**CLIENTE**) O processo de *handshake* começa pelo `CLIENT_HELLO`. Consiste no envio das informações do cliente (definidas na classe `ClientHello`) para o servidor. 
  - **Algoritmo simétrico** 
    - São geradas as chaves do par *Diffie-Hellman*, para estabelecer uma chave secreta partilhada entre o cliente-servidor.
    - A chave pública do *Diffie-Hellman* é enviada para o servidor.
  - **Algoritmo assimétrico**
    - Não é realizada nenhuma operação.
- (**SERVIDOR**) O servidor começa por validar o nome do utilizador escolhido pelo cliente. Caso já exista algum que esse nome, envia um `ServerError`. Caso contrário, gera um `ClientSpec` com as informações do cliente, para além de no:
  - **Algoritmo simétrico**
    - São geradas as chaves do par *Diffie-Hellman*, para estabelecer uma chave secreta partilhada entre o cliente-servidor.
    - Calcula a `sharedPrivateKey` através da chave pública enviada pelo cliente.
  - **Algoritmo assimétrico**
    - Gera uma chave um par *RSA* para comunicar com o cliente.
    - Guarda a chave pública do cliente.
- (**SERVIDOR**) O servidor chega à fase `SERVER_HELLO`. Consiste no envio das informações do servidor (definidas na classe `ServerHello`) para o cliente.
- (**CLIENTE**) Termina o cliente caso receba `ServerError` como resposta. Caso contrário, guarda os dados enviados pelo servidor nos últimos passos.
- (**SERVIDOR**) Informa a todos os clientes que o utilizador entrou (exceto ao próprio).

## Configuração

### Cliente
- `-e, --encryption-algorithms` - Algoritmo de encriptação
- `-k, --key-size` - Tamanho da chave
- `-m, --hashing-algorithm` - Algoritmo de *hash*
- `-n, --name` - Nome do utilizador
- `-h, --host` - Hostname do servidor
- `-p, --port` - Porta do servidor

### Servidor
- `-p, --port` - Porta que o servidor corre
