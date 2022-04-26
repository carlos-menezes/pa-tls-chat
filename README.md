# Cliente

## Configuração inicial

- `host`: str
- `port`: int
- `username`: str
- `keySize`: int[]
- `encryptAlgorithm`: str
- `publicKey`: str
- `usesHash`: bool
- `hashAlgorithm`: str

Esta configuração é definida por parâmetros ao iniciar o programa. O cliente verifica os parâmetros definidos, nomeadamente as combinações entre algoritmo de encriptação e tamanhos de chave. Caso não se verifique nenhuma falha, faz a ligação ao servidor.

## *Handshake*

Aquando da ligação ao servidor, é verificado se o `username` escolhido já existe. A ligação é encerrada se exisitir. Caso contrário, é adicionado a uma lista com os clientes conectados.

## Envio de mensagem

- `encryptedMessage`: str
- `hash`: str
- `destination`: str

A mensagem encriptada é enviada ao servidor, com o utilizador `destination` definido. O servidor fará os seguintes passos:
1. Desencripta a mensagem com o algoritmo definido no *Handshake*
2. Procura a chave pública e algoritmo do `destination`
3. Encripta a mensagem com base em #2
4. Envia a mensagem
