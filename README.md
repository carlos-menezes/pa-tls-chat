# Cliente

## Configuração inicial

- `-h`, `--host`: str
- `-n`, `--name`: str
- `-k`, `--key-sizes`: int[]
- `-e`, `--encryption-algorithms`: str[]
- `-m`, `--hashing-algorithms`: str[]

Esta configuração é definida por parâmetros ao iniciar o programa. O cliente verifica os parâmetros definidos, nomeadamente as combinações entre algoritmo de encriptação e tamanhos de chave. Caso não se verifique nenhuma falha, faz a ligação ao servidor.

## *Handshake*

Aquando da ligação ao servidor, é verificado se o `name` escolhido já existe. A ligação é encerrada se exisitir. Caso contrário, é adicionado a uma lista com os clientes conectados.

## Envio de mensagem

- `encryptedMessage`: str
- `hash`: str
- `destination`: str

A mensagem encriptada é enviada ao servidor, com o utilizador `destination` definido. O servidor fará os seguintes passos:
1. Desencripta a mensagem com o algoritmo definido no *Handshake*
2. Procura a chave pública e algoritmo do `destination`
3. Encripta a mensagem com base em #2
4. Envia a mensagem
