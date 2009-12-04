package edu.gatech.cc.CS4237.gtsecurechat.GUI;

import java.awt.BorderLayout;
import java.awt.Container;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;

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
public class MainChatFrame extends AbstractFrame {

	private static final long serialVersionUID = 4344546169197711305L;
	
	static final Integer FRAME_WIDTH = 300;
	static final Integer FRAME_HEIGHT = 400;
	static final String FRAME_TITLE = "GTSecureChat";
	
	private JTextArea conversationArea, messageArea;
	
	private boolean justSentMessage = false;
	
	public MainChatFrame(final GTSecureChat program) {
		super(program);
		setTitle(FRAME_TITLE);
		setSize(FRAME_WIDTH, FRAME_HEIGHT);
		setResizable(false);
		addWindowListener(new WindowAdapter() {
			public void windowClosing(WindowEvent e) {
				System.exit(0); // though we might want to do something other 
			}                   // than exit when the user clicks the X
		});
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
		menuItem.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				System.exit(0);
			}
		});
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
		messageArea.addKeyListener(new AwesomeListener());
		messageArea.setLineWrap(true);
		messageArea.setWrapStyleWord(true);
		
		JScrollPane conversationScrollPane, newMessageScrollPane;
		conversationScrollPane = new JScrollPane(conversationArea);
		conversationScrollPane.setVerticalScrollBarPolicy(
				JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
		newMessageScrollPane = new JScrollPane(messageArea);
		
		JSplitPane splitPane = new JSplitPane(
				JSplitPane.VERTICAL_SPLIT, 
				conversationScrollPane, 
				newMessageScrollPane);
		splitPane.setDividerLocation(0.75);
		pane.add(BorderLayout.CENTER, splitPane);
	}
	
	protected void receiveMessage(final String message) {
//		conversationArea.append("\n" + messageArea.getText());
		conversationArea.append(message + "\n");
		conversationArea.setCaretPosition(
				conversationArea.getText().length());
	}
	
	private class AwesomeListener implements ActionListener, KeyListener {

		@Override
		public void actionPerformed(final ActionEvent e) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void keyPressed(final KeyEvent e) {
			if (e.getKeyCode() == KeyEvent.VK_ENTER 
					&& messageArea.getText().trim().length() > 0) {
				try {
					program.sendMessage(messageArea.getText());
				} catch (Exception e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
				justSentMessage = true;
			}
		}

		@Override
		public void keyReleased(final KeyEvent e) {
			if (e.getKeyCode() == KeyEvent.VK_ENTER && justSentMessage) {
				messageArea.setText(new String());
				justSentMessage = false;
			}
			// TODO Auto-generated method stub
			
		}

		@Override
		public void keyTyped(final KeyEvent e) {
//			if (e == KeyEvent.)
		}
	}
}
