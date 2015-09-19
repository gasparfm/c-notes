# c-notes /comm

+ myssl.c
  Openssl example fetching a website from a secure server

  Compilation:
    $ gcc -o myssl myssql.c -lcrypto -lssl

  Usage
    $ ./myssl github.com [port]

+ sslserver.c
  Example secure server using openSSL

  Compilation:
    $ gcc -o sslserver sslserver.c -lcrypto -lssl

  Usage
    $ ./sslserver

You can see a beautiful Doxygen-made doc [here](http://gaspar.totaki.com/docs/c_notes_comm/files.php).