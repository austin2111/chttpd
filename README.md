Compiling:

gcc -O2 chttpd.c -o chttpd -L /usr/lib/ -lmicrohttpd -lsqlite3

Currently, the port to access the HTTP server is hardcoded to 8082. If the software is to be containerized, please ensure that stdin/stderr are present, or the program will not be able to run.
