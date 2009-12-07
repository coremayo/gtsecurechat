Beau Bennett
Corey Mayo
CS4237 Fall 2009
Final Project

Our project is a secure peer to peer chat program. It uses symmetric encryption based on a password that is known only by the two users that are chatting. When the program is run by the first user, it listens on a user supplied TCP port. When the second user connects, the program negotiates a key using the password-authenticated key exchange (PAK) variant of Diffie-hellman.

After negotiating a session key, chat traffic is encrypted with our implementation of the International Data Encryption Algorithm (IDEA). We chose to use cipher feedback mode to turn IDEA into a stream cipher capable of encrypting arbitrary length messages.

To run our program, you can simply type: "java -jar target/gtsecurechat-1.0.jar". When the program starts, the first user will select "New Chat". He will then type his chat handle, create a password for the chat session, and also select which port number to listen on. The program will then wait for the second user to connect. When the second user starts the program, he will choose "Join Chat". He will then type his chat handle, the password, and the address and port number to connect to. After the second user connects, the program will automatically negotiate a session key and encrypt all chat traffic.

To compile our program, you will need to have Apache Maven and a recent JDK installed. To compile type "mvn install" from the gtsecurechat directory. This will create a new gtsecurechat-1.0.jar file in the target directory.

Some resources we used:
Password-authedticated key exchange: http://www.itu.int/rec/T-REC-X.1035/en
Network Security: Private Communication in a Public World (class textbook)
