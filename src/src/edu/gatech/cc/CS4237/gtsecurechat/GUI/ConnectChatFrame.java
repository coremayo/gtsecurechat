package edu.gatech.cc.CS4237.gtsecurechat.GUI;

import java.awt.Color;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;

import edu.gatech.cc.CS4237.gtsecurechat.InvalidPasswordException;

public class ConnectChatFrame 
		extends AbstractFrame
		implements ActionListener {

	private static final long serialVersionUID = 1374245625014306217L;
	
	static final int FRAME_WIDTH = 300;
	static final int FRAME_HEIGHT = 500;
	static final String FRAME_TITLE = "Join a Chat";
	
	private JLabel nameLabel, passLabel, hostLabel, portLabel, errorLabel;
	private JTextField nameField, hostField, portField;
	private JPasswordField passField;
	private JButton cancelButton, okayButton;

	public ConnectChatFrame(final GTSecureChat program) {
		super(program);
		setTitle(FRAME_TITLE);
		setSize(FRAME_WIDTH, FRAME_HEIGHT);
		setLocationRelativeTo(null);
		setResizable(false);
		addWindowListener(new WindowAdapter() {
			public void windowClosing(WindowEvent e) {
				setVisible(false);
				errorLabel.setVisible(false);
				program.setActiveWindow(program.WELCOME_WINDOW);
			}
		});

		JPanel panel = new JPanel();
		panel.setLayout(new GridBagLayout());
		GridBagConstraints c = new GridBagConstraints();
		add(panel);
		//TODO make some snazzy borders... panel.setBorder(...
		
		//TODO add chat password field
		
		nameLabel = new JLabel("Name");
		c.fill = GridBagConstraints.NONE;
		c.anchor = GridBagConstraints.NORTHWEST;
		c.gridx = 0;
		c.gridy = 0;
		c.gridwidth = 0;
		c.insets = new Insets(5, 5, 5, 5);
		panel.add(nameLabel, c);
		
		nameField = new JTextField();
		c.fill = GridBagConstraints.HORIZONTAL;
		c.gridx = 0;
		c.gridy = 1;
		c.gridwidth = 3;
		c.insets = new Insets(5, 5, 5, 5);
		panel.add(nameField, c);
		
		passLabel = new JLabel("Password");
		c.fill = GridBagConstraints.NONE;
		c.gridx = 0;
		c.gridy = 2;
		c.gridwidth = 0;
		c.insets = new Insets(5, 5, 5, 5);
		panel.add(passLabel, c);
		
		passField = new JPasswordField();
		c.fill = GridBagConstraints.HORIZONTAL;
		c.gridx = 0;
		c.gridy = 3;
		c.gridwidth = 3;
		c.insets = new Insets(5, 5, 5, 5);
		panel.add(passField, c);
		
		hostLabel = new JLabel("Hostname or IP Address");
		c.fill = GridBagConstraints.NONE;
		c.anchor = GridBagConstraints.NORTHWEST;
		c.gridx = 0;
		c.gridy = 4;
		c.gridwidth = 0;
		c.insets = new Insets(5, 5, 5, 5);
		panel.add(hostLabel, c);
		
		hostField = new JTextField("localhost");
		c.fill = GridBagConstraints.HORIZONTAL;
		c.gridx = 0;
		c.gridy = 5;
		c.gridwidth = 3;
		c.insets = new Insets(5, 5, 5, 5);
		panel.add(hostField, c);
		
		portLabel = new JLabel("Port");
		c.fill = GridBagConstraints.NONE;
		c.gridx = 0;
		c.gridy = 6;
		c.gridwidth = 0;
		c.insets = new Insets(5, 5, 5, 5);
		panel.add(portLabel, c);
		
		portField = new JTextField("8080");
		c.fill = GridBagConstraints.HORIZONTAL;
		c.gridx = 0;
		c.gridy = 7;
		c.gridwidth = 3;
		c.insets = new Insets(5, 5, 5, 5);
		panel.add(portField, c);
		
		cancelButton = new JButton("Cancel");
		cancelButton.addActionListener(this);
		c.fill = GridBagConstraints.HORIZONTAL;
		c.gridx = 1;
		c.gridy = 8;
		c.gridwidth = 1;
		c.insets = new Insets(5, 5, 5, 5);
		panel.add(cancelButton, c);
		
		okayButton = new JButton("OK");
		okayButton.addActionListener(this);
		c.fill = GridBagConstraints.HORIZONTAL;
		c.gridx = 2;
		c.gridy = 8;
		c.gridwidth = 1;
		c.insets = new Insets(5, 5, 5, 5);
		panel.add(okayButton, c);
		
		errorLabel = new JLabel("this is an error");
		errorLabel.setVisible(false);
		errorLabel.setForeground(Color.RED);
		c.fill = GridBagConstraints.HORIZONTAL;
		c.gridx = 0;
		c.gridy = 9;
		c.gridwidth = 1;
		c.insets = new Insets(5, 5, 5, 5);
		panel.add(errorLabel, c);
		
	}

	@Override
	public void actionPerformed(ActionEvent e) {
		if (e.getSource() == cancelButton) {
		// User clicked Cancel
			setVisible(false);
			errorLabel.setVisible(false);
			program.setActiveWindow(program.WELCOME_WINDOW);
			
		} else if (e.getSource() == okayButton) {
		// User clicked OK
			try {
				program.joinChat(nameField.getText(), 
						         hostField.getText(), 
						         portField.getText(),
						         passField.getPassword());
				setVisible(false);
				program.setActiveWindow(program.CHAT_WINDOW);
			} catch (InvalidPasswordException ex) {
				errorLabel.setVisible(true);
				errorLabel.setText(ex.getMessage());
				setVisible(true);
			} catch (Exception ex) {
				errorLabel.setVisible(true);
				errorLabel.setText(ex.getMessage());
				ex.printStackTrace();
				setVisible(true);
			}
		}
	}
}
