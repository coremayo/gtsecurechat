package edu.gatech.cc.cs4237.gtsecurechat.GUI;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

import edu.gatech.cc.cs4237.gtsecurechat.CFBStreamCipher;
import edu.gatech.cc.cs4237.gtsecurechat.IDEABlockCipher;
import edu.gatech.cc.cs4237.gtsecurechat.IStreamCipher;
import edu.gatech.cc.cs4237.gtsecurechat.InvalidPasswordException;
import edu.gatech.cc.cs4237.gtsecurechat.network.CryptoInputStream;
import edu.gatech.cc.cs4237.gtsecurechat.network.CryptoOutputStream;
import edu.gatech.cc.cs4237.gtsecurechat.network.Handshake;

/**
 * 
 * @author corey
 *
 */
public class GTSecureChat {
	
	private Handshake handshake;
	private IStreamCipher crypto;
	private CryptoOutputStream out;
	private CryptoInputStream in;
	private Socket sock;
	
	/**
	 * Number of bytes in an initialization vector.
	 */
	protected final int IV_SIZE = 8;
	
	/**
	 * Identities of Alice and Bob.
	 */
	private String alice = "Alice", bob = "Bob";
	
	/**
	 * Chat handle of the user.
	 */
	private String name;

	protected ConnectChatFrame CONNECT_WINDOW;
	protected CreateChatFrame CREATE_WINDOW;
	protected MainChatFrame CHAT_WINDOW;
	protected WelcomeFrame WELCOME_WINDOW;
	
	public GTSecureChat() {
		CONNECT_WINDOW = new ConnectChatFrame(this);
		CREATE_WINDOW = new CreateChatFrame(this);
		CHAT_WINDOW = new MainChatFrame(this);
		WELCOME_WINDOW = new WelcomeFrame(this);
		WELCOME_WINDOW.setVisible(true);
	}
	
	/**
	 * We're Bob; we listen for Alice to connect.
	 * @param name Bob's actual name
	 * @param port TCP port number to listen on
	 * @param pass password for chat
	 * @throws IOException if something in the network failed
	 */
	protected void createNewChat(String name, int port, char[] pass) 
			throws IOException {

		this.name = name;
		
		// Set up some networking.
		ServerSocket srvSock = new ServerSocket(port);
		
		// We use a thread here so that while Bob is waiting for Alice to 
		// connect, we can still interact with the user. Otherwise, the program 
		// would appear to be frozen to the user.
		HandshakeResponder hr = new HandshakeResponder(pass, srvSock);
		Thread handshakeThread = new Thread(hr);
		handshakeThread.start();
		
		// Notify the user that we're waiting.
		CHAT_WINDOW.setStatus("Waiting for someone to connect");
	}

	/**
	 * We're Alice; we need to connect to Bob.
	 * @param name Alice's chat handle
	 * @param host Bob's IP address or host name
	 * @param port TCP port number bob is listening on
	 * @param pass password for chat
	 * @throws Exception
	 */
	protected void joinChat(String name, 
			                String host, 
			                int port, 
			                char[] pass) 
			throws InvalidPasswordException, IOException {
		
		// We don't use a separate thread like we do with Bob's side.
		// If we did, then the main chat window could come up even if the 
		// key negotiation fails. We want the password entry screen to remain 
		// visible so that we can prompt Alice to retype the password if needed.
		this.name = name;
		handshake = new Handshake(alice, bob, pass);
		sock = new Socket(host, port);
		
		try {
			// Get the initial message of the handshake and sends it to Bob.
			byte[] m1 = handshake.m1();
			sock.getOutputStream().write(m1);
		
			// Read Bob's response, the second message of the handshake.
			int m2Len = handshake.getM2Length();
			byte[] m2 = new byte[m2Len];
			if (sock.getInputStream().read(m2, 0, m2Len) != m2Len) {
				sock.close();
				throw new IOException("Alice received a bad m2 from Bob");
			}

			// Get the final message of the handshake and send it to Bob.
			byte[] m3 = handshake.m3(m2);
			sock.getOutputStream().write(m3);
			
		// This will occur if Alice typed a bad password. If this happens, we 
		// need to let Bob know that we are restarting the handshake and then 
		// let the user know.
		} catch (InvalidPasswordException e) {
			sock.getOutputStream().write(new byte[handshake.getM3Length()]);
			sock.close();
			throw e;
			
		// This will probably only occur due to network problems.
		} catch (HandshakeException e) {
			throw new IOException(e);
		}
		
		// After performing the handshake, proceed to set up the CryptoStreams.
		initializeCryptoStreams();
	}

	/**
	 * After negotiating the key, Alice and Bob will each call this function to 
	 * initialize the CryptoInputStream and CryptoOutputStrem. This method also 
	 * spawns a new thread which listens for messages sent by the other side.
	 * @throws IOException If network problems occur
	 */
	private void initializeCryptoStreams() throws IOException {
		
		byte[] key = handshake.getKey();
		handshake.destroy();
		
		crypto = new CFBStreamCipher(new IDEABlockCipher());
		crypto.initialize(key);
		
		out = new CryptoOutputStream(sock.getOutputStream(), crypto);
		in = new CryptoInputStream(sock.getInputStream(), crypto);
		
		new Thread(new MessageListener()).start();
	}

	/**
	 * This method will be called by the user interface. It will send a message 
	 * to the CryptoOutputStream which will then pass it onto the network.
	 * @param plain Plain text of the message.
	 * @throws IOException If network issues occur.
	 */
	protected void sendMessage(String plain) throws IOException {
		if (out != null) {
			plain = name + ": " + plain;
			out.println(plain);
			CHAT_WINDOW.receiveMessage(plain);
		}
	}
	
	protected void endChat() {
		try {
			sock.close();
		} catch (IOException e) {
//			e.printStackTrace();
		}
		out = null;
		in = null;
		CHAT_WINDOW.setVisible(false);
		WELCOME_WINDOW.setVisible(true);
	}

	/**
	 * This class is used by both Alice and Bob. After negotiating a key, they 
	 * each will create an instance of this class then call 
	 * "(new Thread(instance)).start();" This will listen on the 
	 * CryptoInputStream for a message then pass that message to the GUI.<br>
	 * As soon as the TCP connection is ended, System.exit(0) will be called.
	 * @author corey
	 *
	 */
	private class MessageListener implements Runnable {
		@Override
		public void run() {
			String message;
			
			// Wait for a message to be received then copy it to the chat window
			while ((message = in.readLine()) != null) {
				
				// Only do something if it isn't an empty string.
				if (!message.equals("")) {
					CHAT_WINDOW.receiveMessage(message);
				}
			}
			
			// When the TCP connection closes, then exit
			endChat();
		}
	}
	
	/**
	 * This class will be used by Bob. After opening a server socket to listen, 
	 * Bob will want to wait for Alice to initiate the handshake.
	 * @author corey
	 *
	 */
	private class HandshakeResponder implements Runnable {

		private char[] pass;
		private ServerSocket srvSock;
		
		private HandshakeResponder(char[] pass, ServerSocket srvSock) {
			this.pass = pass;
			this.srvSock = srvSock;
		}
		
		@Override
		public void run() {
			try {
				boolean success = false;
				
				// Keep trying until the handshake succeeds
				while(!success) {
					success = true;
					
					// Each time we fail, start the handshake all over
					handshake = new Handshake(alice, bob, pass);
					
					// Wait for Alice.
					sock = srvSock.accept();
					try {
						
						// Get the initial message of the Handshake from Alice
						int m1Len = handshake.getM1Length();
						byte[] m1 = new byte[m1Len];
						if (sock.getInputStream().read(m1, 0, m1Len) != m1Len) {
							sock.close();
							throw new IOException(
									"Bob received a bad m1 from Alice");
						}
						// Notify the user that we're talking to Alice.
						CHAT_WINDOW.setStatus("Negotiating key");
						
						// Generate our response and send it to Alice.
						// Second message of handshake.
						byte[] m2 = handshake.m2(m1);
						sock.getOutputStream().write(m2);
						
						// Get Alice's response, final message of handshake.
						int m3Len = handshake.getM3Length();
						byte[] m3 = new byte[m3Len];
						if (sock.getInputStream().read(m3, 0, m3Len) != m3Len) {
							sock.close();
							throw new IOException (
									"Bob received a bad m3 from Alice");
						}
						
						// Check to make sure Alice's response is good and
						// generate session key.s
						handshake.m4(m3);
						
					// This will probably only occur due to network issues.
					} catch (HandshakeException e) {
						throw new IOException(e);
						
					// Handshake failed due to a bad password.
					} catch (InvalidPasswordException e) {
						// We start the handshake over.
						success = false;
						
						// Notify the user that we're waiting.
						CHAT_WINDOW.setStatus("Waiting for someone to connect");
					}
				}
				// We're done with the handshake, so clear the status.
				CHAT_WINDOW.setStatus(null);
				
				// Initialize the CryptoStreams.
				initializeCryptoStreams();

			// Some network issues occurred.
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}
}
