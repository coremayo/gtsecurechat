package edu.gatech.cc.CS4237.gtsecurechat.network;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;

import edu.gatech.cc.CS4237.gtsecurechat.GUI.GTSecureChat;

public class ChatNetwork implements Runnable {
	
	private GTSecureChat program;
	private Socket sock;
	private ServerSocket srvSock;
	private BufferedReader in;
	private PrintStream out;
	
	/**
	 * Listens on a specific port.
	 * @param program
	 * @param port
	 * @throws IOException
	 */
	public ChatNetwork(GTSecureChat program, int port) throws IOException {
		this.program = program;
		srvSock = new ServerSocket(port);
	}
	
	/**
	 * Connects to a specific host:port.
	 * @param program
	 * @param host
	 * @param port
	 * @throws UnknownHostException
	 * @throws IOException
	 */
	public ChatNetwork(GTSecureChat program, String host, int port) 
			throws UnknownHostException, IOException {
		this.program = program;
		sock = new Socket(host, port);
	}
	
	/**
	 * Sends the provided byte array.
	 * 
	 * @param message
	 * @throws IOException
	 */
	public void sendMessage(final byte[] message) throws IOException {
		out.write(message);
	}

	@Override
	public void run() {
		try {
			if (sock == null && srvSock != null) {
				sock = srvSock.accept();
			}
			in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
			out = new PrintStream(sock.getOutputStream());
			
			String message;
			while((message = in.readLine()) != null && !message.equals("quit")) {
				program.receiveMessage(message.getBytes());
			}
			System.exit(0);
		} catch (IOException e) {
			e.printStackTrace();
			//TODO some error handling, maybe sock.close(); ?
		}
	}
	
	public InetAddress getLocalAddress() {
		return sock.getLocalAddress();
	}
	
	public InetAddress getRemoteAddress() {
		return sock.getInetAddress();
	}
	
	public int getLocalPort() {
		return sock.getLocalPort();
	}
	
	public int getRemotePort() {
		return sock.getPort();
	}
}
