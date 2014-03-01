RSA-server-client
================

1. This project ensures secure communication using sockets in C/C++ using the RSA encryption-decryption algorithm. The sender runs the server code and the rreceiver runs the client code. The authenticity of the sender is checked using a digital signature scheme using the SHA1 (Secure Hash Algorithm).

2. The code needs GMP(big number arithmetic library to compile.

3. The code can be compiled either in separate machines(or even in the same) connected over a network (LAN).

4. One system acts as a server and runs server code. The other runs client code. Since the project was to send a specific log file securely over a network the name of the file being input.txt in cwd. The path can be hard-coded and changed in client3.cpp.

5. The output can be seen on the server's cwd as output.txt.

6. To compiling and run use: g++ -lgmp server3.cpp -o server
			     ./server

7. Similarly for client.
