package edu.gatech.cc.CS4237.gtsecurechat.GUI;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

import javax.swing.JFrame;

import edu.gatech.cc.CS4237.gtsecurechat.DummyEncryption;
import edu.gatech.cc.CS4237.gtsecurechat.IStreamCipher;
import edu.gatech.cc.CS4237.gtsecurechat.InvalidPasswordException;
import edu.gatech.cc.CS4237.gtsecurechat.network.CryptoInputStream;
import edu.gatech.cc.CS4237.gtsecurechat.network.CryptoOutputStream;
import edu.gatech.cc.CS4237.gtsecurechat.network.Handshake;

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
	protected final int IV_SIZE = 8; //TODO move this to IStreamCipher interface
	
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
		
		setActiveWindow(WELCOME_WINDOW);
	}
	
	protected void setActiveWindow(JFrame window) {
		window.setVisible(true);
	}
	
	/**
	 * We're Bob; we listen for Alice to connect.
	 * @param name Bob's actual name
	 * @param portName port number to listen on
	 * @param pass password for chat
	 * @throws Exception
	 */
	protected void createNewChat(String name, int port, char[] pass) 
			throws IOException {

		this.name = name;
		ServerSocket srvSock = new ServerSocket(port);
		HandshakeResponder hr = new HandshakeResponder(pass, srvSock);
		Thread handshakeThread = new Thread(hr);
		handshakeThread.start();
		CHAT_WINDOW.setStatus("Waiting for someone to connect");
	}

	/**
	 * We're Alice; we need to connect to Bob.
	 * @param name Alice's actual name
	 * @param host Bob's IP address or hostname
	 * @param portName port number bob is listening on
	 * @param pass password for chat
	 * @throws Exception
	 */
	protected void joinChat(String name, 
			                String host, 
			                int port, 
			                char[] pass) 
			throws InvalidPasswordException, IOException {
		
		this.name = name;
		int m3Size = 16;
		handshake = new Handshake(alice, bob, pass);
		sock = new Socket(host, port);
		
		byte[] m1;
		try {
			m1 = handshake.m1();
			sock.getOutputStream().write(m1);
		
			int m2Size = 129 + 16;
			byte[] m2 = new byte[m2Size];
			if (sock.getInputStream().read(m2, 0, m2Size) != m2Size) {
				sock.close();
				throw new IOException("Alice received a bad m2 from Bob");
			}
			System.out.println("Alice got m2");
		
			byte[] m3 = handshake.m3(m2);
			sock.getOutputStream().write(m3);
		} catch (InvalidPasswordException e) {
			sock.getOutputStream().write(new byte[m3Size]);
			sock.close();
			throw e;
		} catch (HandshakeException e) {
			throw new IOException(e);
		}
		
		initializeCryptoStreams();
		
//		// clear out the password when we're done
//		for (int i = 0; i < pass.length; i++) {
//			pass[i] = '\0';
//		}
	}
	
	private void initializeCryptoStreams() throws IOException {
		
		byte[] key = handshake.getKey();
		handshake.destroy();
		
		//TODO when IDEA is ready, insert actual encryption here
		crypto = new DummyEncryption();
		crypto.initialize(key);
		
		out = new CryptoOutputStream(sock.getOutputStream(), crypto);
		in = new CryptoInputStream(sock.getInputStream(), crypto);
		
		new Thread(new MessageListener()).start();
	}

	protected void sendMessage(String plain) throws IOException {
		plain = name + ": " + plain;
		out.println(plain);
		CHAT_WINDOW.receiveMessage(plain);
	}

	private class MessageListener implements Runnable {
		@Override
		public void run() {
			String message;
			while ((message = in.readLine()) != null) {
				CHAT_WINDOW.receiveMessage(message);
			}
			System.exit(0);
		}
	}
	
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
				while(!success) {
					success = true;
					handshake = new Handshake(alice, bob, pass);
					sock = srvSock.accept();
					try {
						int m1Size = alice.length() + 129;
						byte[] m1 = new byte[m1Size];
						if (sock.getInputStream().read(m1, 0, m1Size) != m1Size) {
							sock.close();
							throw new IOException("Bob received a bad m1 from Alice");
						}
						CHAT_WINDOW.setStatus("Negotiating key");
						System.out.println("Bob got m1");
						
						byte[] m2 = handshake.m2(m1);
						sock.getOutputStream().write(m2);
						
						int m3Size = 16;
						byte[] m3 = new byte[m3Size];
						if (sock.getInputStream().read(m3, 0, m3Size) != m3Size) {
							sock.close();
							throw new IOException ("Bob received a bad m3 from Alice");
						}
						System.out.println("Bob got m3");
						
						handshake.m4(m3);
						
					} catch (HandshakeException e) {
						throw new IOException(e);
					} catch (InvalidPasswordException e) {
						// basically, every time authentication failed because of a bad 
						// password we start the handshake over
						success = false;
						System.out.println("Alice sent us a bad password");
					}
				}
				CHAT_WINDOW.setStatus(null);
				initializeCryptoStreams();

			} catch (IOException e) {
				e.printStackTrace();
				//TODO come up with what to do if network stuff fails
			}
		}
	}
}
