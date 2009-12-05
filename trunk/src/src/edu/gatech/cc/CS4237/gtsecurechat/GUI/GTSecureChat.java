package edu.gatech.cc.CS4237.gtsecurechat.GUI;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.SecureRandom;

import javax.swing.JFrame;

import edu.gatech.cc.CS4237.gtsecurechat.DummyEncryption;
import edu.gatech.cc.CS4237.gtsecurechat.IStreamCipher;
import edu.gatech.cc.CS4237.gtsecurechat.InvalidPasswordException;
import edu.gatech.cc.CS4237.gtsecurechat.network.ChatNetwork;
import edu.gatech.cc.CS4237.gtsecurechat.network.Handshake;

/**
 * 
 * @author corey
 *
 */
public class GTSecureChat {
	
	/**
	 * 128-bit key derived from the handshake.
	 */
	private byte[] sessionKey;
	private Handshake handshake;
	private IStreamCipher crypto;
	
	/**
	 * Number of bytes in an initialization vecotor.
	 */
	protected final int IV_SIZE = 8;
	
	private SecureRandom rand;
	private ChatNetwork network;
	private Thread thread;
	
	private String alice, bob;
	
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
		
		rand = new SecureRandom();
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
	protected void createNewChat(String name, 
			                     String portName, 
			                     char[] pass) 
			throws IOException {
		
		this.alice = "Alice";
		this.bob = "Bob";
		this.name = name;
		
		// port number to listen on
		int port = Integer.parseInt(portName);
		
		ServerSocket srvSock = new ServerSocket(port);
		Socket sock = null;
		
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
				
				try {
					byte[] m2 = handshake.m2(m1);
					sock.getOutputStream().write(m2);
				} catch (HandshakeException e) {
					throw new IOException(e);
				}
				
				int m3Size = 16;
				byte[] m3 = new byte[m3Size];
				if (sock.getInputStream().read(m3, 0, m3Size) != m3Size) {
					sock.close();
					throw new IOException ("Bob received a bad m3 from Alice");
				}
				
				try {
					handshake.m4(m3);
				} catch (HandshakeException e) {
					throw new IOException(e);
				}
			} catch (InvalidPasswordException e) {
				// basically, every time authentication failed because of a bad 
				// password we start the handshake over
				success = false;
				System.out.println("Alice sent us a bad password");
			}
		}
		
		sessionKey = handshake.getKey();
		handshake.destroy();
		
		//TODO insert IDEA here, when ready
		crypto = new DummyEncryption();
		crypto.initialize(sessionKey);
		
		network = new ChatNetwork(this, sock);
		thread = new Thread(network);
		thread.start();
		System.out.println("Listening on port " + port);
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
			                String portName, 
			                char[] pass) 
			throws InvalidPasswordException, IOException {
		/* 
		 * TODO make this method into a thread. 
		 * That way, we can present the user with some sort of waiting screen 
		 * while we are waiting for alice to connect.
		 */
		
		this.alice = "Alice";
		this.bob = "Bob";
		this.name = name;
		
		// TODO error handling?
		handshake = new Handshake(alice, bob, pass);
		
		// port that Bob is listening on
		int port = Integer.parseInt(portName);
		Socket sock = new Socket(host, port);
		
		byte[] m1;
		try {
			m1 = handshake.m1();
		} catch (HandshakeException e) {
			throw new IOException(e);
		}
		sock.getOutputStream().write(m1);
		
		int m2Size = 129 + 16;
		byte[] m2 = new byte[m2Size];
		if (sock.getInputStream().read(m2, 0, m2Size) != m2Size) {
			sock.close();
			throw new IOException("Alice received a bad m2 from Bob");
		}
		
		int m3Size = 16;
		try {
			byte[] m3 = handshake.m3(m2);
			sock.getOutputStream().write(m3);
		} catch (InvalidPasswordException e) {
			sock.getOutputStream().write(new byte[m3Size]);
			sock.close();
			throw e;
		} catch (HandshakeException e) {
			throw new IOException(e);
		}
		
		sessionKey = handshake.getKey();
		handshake.destroy();
		
		//TODO when IDEA is ready, insert actual encryption here
		crypto = new DummyEncryption();
		crypto.initialize(sessionKey);
		
		network = new ChatNetwork(this, sock);
		thread = new Thread(network);
		thread.start();
		System.out.println("Connected to " + host + " on port " + port);
	}

	protected void sendMessage(String plain) throws Exception {
		plain = name + ": " + plain;
		byte[] iv = new byte[IV_SIZE];
		rand.nextBytes(iv);
		byte[] cipher = crypto.encrypt(plain, iv);
		
		//TODO actually send an iv
		network.sendMessage(new String(cipher));
		CHAT_WINDOW.receiveMessage(plain);
	}
	
	public void receiveMessage(byte[] cipher) {
		//TODO actually receive an iv
		byte[] iv = new byte[0];
		String plain = crypto.decrypt(cipher, iv);
		CHAT_WINDOW.receiveMessage(plain);
	}
}
