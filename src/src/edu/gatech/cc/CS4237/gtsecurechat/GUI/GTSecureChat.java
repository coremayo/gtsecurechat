package edu.gatech.cc.CS4237.gtsecurechat.GUI;

import java.net.ServerSocket;
import java.net.Socket;

import javax.swing.JFrame;

import edu.gatech.cc.CS4237.gtsecurechat.network.ChatNetwork;
import edu.gatech.cc.CS4237.gtsecurechat.network.Handshake;

/**
 * 
 * @author corey
 *
 */
public class GTSecureChat {
	
	/**
	 * If true, we're Alice. If false, we're Bob.<br />
	 * If we are the initiator, we will be sending messages 1 and 3 of the 
	 * handshake. Otherwise, we will be sending 2 and 4.
	 */
	private boolean initiator;
	
	/**
	 * 128-bit key derived from the handshake.
	 */
	private byte[] sessionKey;
	private byte[] m1, m2, m3, m4;
	private Handshake handshake;
	
	private ChatNetwork network;
	private Thread thread;
	
	private String alice, bob;

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
	protected void createNewChat(String name, 
			                     String portName, 
			                     char[] pass) 
			throws Exception {
		
		initiator = false;
		this.alice = "Alice";
		this.bob = "Bob";
		
		//TODO error handling?
		handshake = new Handshake(alice, bob, pass);
		
		// port number to listen on
		int port = Integer.parseInt(portName);
		
		ServerSocket srvSock = new ServerSocket(port);
		Socket sock = srvSock.accept();
		
		int m1Size = alice.length() + 129;
		m1 = new byte[m1Size];
		if (sock.getInputStream().read(m1, 0, m1Size) != m1Size) {
			throw new Exception("Bob received a bad m1 from Alice");
		}
		
		m2 = handshake.m2(m1);
		sock.getOutputStream().write(m2);
		
		int m3Size = 16;
		m3 = new byte[m3Size];
		if (sock.getInputStream().read(m3, 0, m3Size) != m3Size) {
			throw new Exception ("Bob received a bad m3 from Alice");
		}
		
		handshake.m4(m3);
		
		sessionKey = handshake.getKey();
		handshake.destroy();
		
		System.out.println("  Bob key: 0x" + Handshake.byteArrayToHexString(sessionKey));
		
		// this form of the constructor creates a new socket and listens.
//		network = new ChatNetwork(this, port);
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
			throws Exception {
		
		initiator = true;
		this.alice = "Alice";
		this.bob = "Bob";
		
		// TODO error handling?
		handshake = new Handshake(alice, bob, pass);
		
		// port that Bob is listening on
		int port = Integer.parseInt(portName);
		
		Socket sock = new Socket(host, port);
		
		m1 = handshake.m1();
		sock.getOutputStream().write(m1);
		
		int m2Size = 129 + 16;
		m2 = new byte[m2Size];
		if (sock.getInputStream().read(m2, 0, m2Size) != m2Size) {
			throw new Exception("Alice received a bad m2 from Bob");
		}
		
		m3 = handshake.m3(m2);
		sock.getOutputStream().write(m3);
		
//		int m4Size = 16;
//		m4 = new byte[m4Size];
//		if (sock.getInputStream().read(m4, 0, m4Size) != m4Size) {
//			throw new Exception("Alice received a bad m4 from Bob");
//		}
		
		sessionKey = handshake.getKey();
		handshake.destroy();
		
		System.out.println("Alice key: 0x" + Handshake.byteArrayToHexString(sessionKey));
		
//		network = new ChatNetwork(this, host, port);
		network = new ChatNetwork(this, sock);
		thread = new Thread(network);
		thread.start();
		System.out.println("Connected to " + host + " on port " + port);
		
//		m1 = handshake.m1();
//		network.sendMessage(new String(m1));
	}

	protected void sendMessage(String message) throws Exception {
		//TODO actually send an encrypted message here
		network.sendMessage(message);
		CHAT_WINDOW.receiveMessage(message);
	}
	
	public void receiveMessage(byte[] message) {
//		try {
//			if (!initiator && m2 == null) {
//				m2 = handshake.m2(message);
//				network.sendMessage(new String(m2));
//			} else if (initiator && m3 == null) {
//				m3 = handshake.m3(message);
//				sessionKey = handshake.getKey();
//				System.out.println("Alice key: 0x" + Handshake.byteArrayToHexString(sessionKey));
//				network.sendMessage(new String(m3));
//			} else if (!initiator && sessionKey == null) {
//				handshake.m4(message);
//				sessionKey = handshake.getKey();
//				System.out.println("  Bob key: 0x" + Handshake.byteArrayToHexString(sessionKey));
//			} else {
				CHAT_WINDOW.receiveMessage(new String(message));
//			}
//		} catch (Exception e) {
//			e.printStackTrace();
//		}
	}
}
