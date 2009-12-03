package edu.gatech.cc.CS4237.gtsecurechat.GUI;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JPanel;

public class WelcomeFrame 
		extends AbstractFrame
		implements ActionListener {

	private static final long serialVersionUID = 9202766616765285702L;
	
	static final int FRAME_WIDTH = 250;
	static final int FRAME_HEIGHT = 100;
	static final String FRAME_TITLE = "GTSecureChat";
	
	private JButton newChatButton, joinChatButton;
	
	public WelcomeFrame(GTSecureChat program) {
		super(program);
		setTitle(FRAME_TITLE);
		setSize(FRAME_WIDTH, FRAME_HEIGHT);
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setLocationRelativeTo(null);
		setResizable(false);

		JPanel panel = new JPanel();
		panel.setLayout(new GridBagLayout());
		GridBagConstraints c = new GridBagConstraints();
		add(panel);
		
		newChatButton = new JButton("New Chat");
		newChatButton.addActionListener(this);
		c.fill = GridBagConstraints.HORIZONTAL;
		c.gridx = 0;
		c.gridy = 1;
		c.insets = new Insets(0, 0, 0, 10);
		panel.add(newChatButton, c);
		
		joinChatButton = new JButton("Join Chat");
		joinChatButton.addActionListener(this);
		c.gridx = 1;
		c.gridy = 1;
		c.insets = new Insets(0, 0, 0, 0);
		panel.add(joinChatButton, c);
	}

	@Override
	public void actionPerformed(ActionEvent e) {
		if (e.getSource() == newChatButton) {
			setVisible(false);
			program.setActiveWindow(program.CREATE_WINDOW);
		} else if (e.getSource() == joinChatButton) {
			setVisible(false);
			program.setActiveWindow(program.CONNECT_WINDOW);
		}
	}
}
