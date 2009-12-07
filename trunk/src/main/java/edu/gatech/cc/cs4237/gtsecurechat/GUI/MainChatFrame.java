package edu.gatech.cc.cs4237.gtsecurechat.GUI;

import java.awt.BorderLayout;
import java.awt.Container;
import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.awt.event.WindowEvent;
import java.awt.event.WindowListener;
import java.io.IOException;

import javax.swing.JLabel;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTextArea;
import javax.swing.KeyStroke;

/**
 * The main gui for gtsecurechat.
 * @author corey
 *
 */
public class MainChatFrame extends AbstractFrame 
		implements ActionListener, KeyListener, WindowListener {

	private static final long serialVersionUID = 4344546169197711305L;
	
	static final Integer FRAME_WIDTH = 300;
	static final Integer FRAME_HEIGHT = 400;
	static final String FRAME_TITLE = "GTSecureChat";
	
	private JTextArea conversationArea, messageArea;
	private JLabel statusLabel;
	
	public MainChatFrame(final GTSecureChat program) {
		super(program);
		setTitle(FRAME_TITLE);
//		setSize(FRAME_WIDTH, FRAME_HEIGHT);
		setResizable(false);
		addWindowListener(this);
		Container pane = getContentPane();
		
		/* Now the menu bar... File, Edit, Help */
		JMenuBar menuBar = new JMenuBar();
		JMenuItem menuItem;
		pane.add(BorderLayout.NORTH, menuBar);

		JMenu fileMenu = new JMenu("File");
		fileMenu.setMnemonic(KeyEvent.VK_F);
		menuItem = new JMenuItem("Exit", KeyEvent.VK_X);
		menuItem.setAccelerator(
				KeyStroke.getKeyStroke(KeyEvent.VK_Q, ActionEvent.CTRL_MASK));
		menuItem.addActionListener(this);
		fileMenu.add(menuItem);
		menuBar.add(fileMenu);
		
		JMenu editMenu = new JMenu("Edit");
		editMenu.setMnemonic(KeyEvent.VK_E);
		menuBar.add(editMenu);
		
		JMenu helpMenu = new JMenu("Help");
		helpMenu.setMnemonic(KeyEvent.VK_H);
		menuBar.add(helpMenu);
		/* End of the menu bar area */
		
		conversationArea = new JTextArea(20, 20);
		conversationArea.setEditable(false);
		conversationArea.setLineWrap(true);
		conversationArea.setWrapStyleWord(true);
		messageArea = new JTextArea();
		messageArea.addKeyListener(this);
		messageArea.setLineWrap(true);
		messageArea.setWrapStyleWord(true);
		
		JScrollPane conversationScrollPane, messageScrollPane;
		conversationScrollPane = new JScrollPane(conversationArea);
		conversationScrollPane.setVerticalScrollBarPolicy(
				JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
		conversationScrollPane.setMinimumSize(new Dimension(FRAME_WIDTH, 150));
		messageScrollPane = new JScrollPane(messageArea);
		messageScrollPane.setMinimumSize(new Dimension(FRAME_WIDTH, 30));
		
		JSplitPane splitPane = new JSplitPane(
				JSplitPane.VERTICAL_SPLIT, 
				conversationScrollPane, 
				messageScrollPane);
		splitPane.setDividerLocation(300);
		pane.add(BorderLayout.CENTER, splitPane);
		
		statusLabel = new JLabel("HELLO");
		statusLabel.setVisible(false);
		pane.add(BorderLayout.SOUTH, statusLabel);
		pack();
	}
	
	protected void receiveMessage(final String message) {
		conversationArea.append(message + "\n");
		conversationArea.setCaretPosition(
				conversationArea.getText().length());
	}
	
	protected void setStatus(final String status) {
		if (status == null) {
			statusLabel.setVisible(false);
		} else {
			statusLabel.setText(status);
			statusLabel.setVisible(true);
		}
	}

	/**
	 * Performs any necessary cleanup then exits the program.
	 */
	private void exitProgram() {
		System.exit(0);
	}
	
	@Override
	public void keyPressed(final KeyEvent e) {
		if (e.getKeyCode() == KeyEvent.VK_ENTER 
				&& messageArea.getText().trim().length() > 0) {
			try {
				program.sendMessage(messageArea.getText());
			} catch (IOException e1) {
				// TODO handle network problems
				e1.printStackTrace();
			}
		}
	}

	@Override
	public void keyReleased(final KeyEvent e) {
		if (e.getKeyCode() == KeyEvent.VK_ENTER) {
			messageArea.setText(new String());
		}
	}

	@Override
	public void keyTyped(final KeyEvent e) { }

	@Override
	public void actionPerformed(final ActionEvent e) {
		if (e.getSource() instanceof JMenuItem) {
			JMenuItem source = (JMenuItem)e.getSource();
			if (source.getText().equals("Exit")) {
				exitProgram();
			}
		}
	}

	@Override
	public void windowActivated(final WindowEvent arg0) { }

	@Override
	public void windowClosed(final WindowEvent arg0) { }

	@Override
	public void windowClosing(final WindowEvent arg0) {
		exitProgram();
	}

	@Override
	public void windowDeactivated(final WindowEvent arg0) { }

	@Override
	public void windowDeiconified(final WindowEvent arg0) { }

	@Override
	public void windowIconified(final WindowEvent arg0) { }

	@Override
	public void windowOpened(final WindowEvent arg0) { }
}
