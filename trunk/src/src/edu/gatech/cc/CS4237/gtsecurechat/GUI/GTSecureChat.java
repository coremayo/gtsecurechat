package edu.gatech.cc.CS4237.gtsecurechat.GUI;

import javax.swing.JFrame;

public class GTSecureChat {

	protected ConnectChatFrame CONNECT_WINDOW;
	protected CreateChatFrame CREATE_WINDOW;
	protected MainChatFrame MAIN_WINDOW;
	protected WelcomeFrame WELCOME_WINDOW;
	
	public GTSecureChat() {
		CONNECT_WINDOW = new ConnectChatFrame(this);
		CREATE_WINDOW = new CreateChatFrame(this);
		MAIN_WINDOW = new MainChatFrame(this);
		WELCOME_WINDOW = new WelcomeFrame(this);
		
		setActiveWindow(WELCOME_WINDOW);
	}
	
	protected void setActiveWindow(JFrame newWindow) {
		newWindow.setVisible(true);
	}
	
	protected void createNewChat(String name, String port) throws Exception {
		//TODO create some sockets
	}

	public void joinChat(String name, String host, String port) {
		// TODO create some sockets
		
	}
}
