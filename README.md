Compiling:

gcc -O2 httpd_test.c -o httpd_test -L /usr/lib/ -lmicrohttpd

Alternatively, replace /usr/lib with the path if your libmicrohttpd directory. Also, install the libmicrohttpd library.

API:

GET requests:
-------------

No parameters or any other information are needed for these; simply making a request in your browser to, say, http://host/mem is all you'll need. These use commands for a generalized Linux environment, and may not be available for other operating systems.

/mem

This returns physical and swap memory information for the host system. This is equivalent to running the free command on a system.

/cpuinfo

Returns information on CPU cores for the given system. Output is limited to 15743 characters; very lengthy outputs may be truncated.

/diskspace

Returns information on free disk space for the given system.

POST requests:
--------------

/lower

Any upper case characters in the request body will be returned as lower case letters in the response. For example, qwerTYUIOp!@#1 will be returned as qwertyuiop!@#1. While a parameter name is required in the POST body, it  will simply be stripped regardless of its name. For example, a POST body of a=testSTRING or request=testSTRING will both return 200 OK with teststring in the response body. If any trouble is encountered, a GET request to / will return an HTTP form to call the function through a browser.
