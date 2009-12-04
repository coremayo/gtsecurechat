package edu.gatech.cc.CS4237.gtsecurechat.GUI;

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
	private Handshake handshake;
	
	private ChatNetwork network;
	private Thread thread;

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
		
		//TODO error handling?
		handshake = new Handshake("Alice", "Bob", pass);
		
		// port number to listen on
		int port = Integer.parseInt(portName);
		
		// this form of the constructor creates a new socket and listens.
		network = new ChatNetwork(this, port);
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
		
		initiator = false;
		
		// TODO error handling, diffie-hellman
		int port = Integer.parseInt(portName);
		network = new ChatNetwork(this, host, port);
		thread = new Thread(network);
		thread.start();
		System.out.println("Connected to " + host + " on port " + port);
	}

	protected void sendMessage(String message) throws Exception {
		//TODO actually send an encrypted message here
		network.sendMessage((message+"\n").getBytes());
		CHAT_WINDOW.receiveMessage(message);
	}
	
	public void receiveMessage(byte[] message) {
		CHAT_WINDOW.receiveMessage(new String(message));
	}
}
