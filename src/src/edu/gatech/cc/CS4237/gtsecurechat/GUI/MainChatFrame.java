package edu.gatech.cc.CS4237.gtsecurechat.GUI;

import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;

import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTextArea;


/**
 * The main gui for gtsecurechat.
 * @author corey
 *
 */
public class MainChatFrame extends AbstractFrame {

	private static final long serialVersionUID = 4344546169197711305L;
	
	static final Integer FRAME_HEIGHT = 500;
	static final Integer FRAME_WIDTH = 300;
	static final String FRAME_TITLE = "GTSecureChat";
	
	private JTextArea conversationTextArea, newMessageTextArea;
	
	public MainChatFrame(final GTSecureChat program) {
		super(program);
		setTitle(FRAME_TITLE);
		setSize(FRAME_WIDTH, FRAME_HEIGHT);
		addWindowListener(new WindowAdapter() {
			public void windowClosing(WindowEvent e) {
				setVisible(false);
				program.setActiveWindow(program.WELCOME_WINDOW);
			}
		});
		
		JPanel panel = new JPanel();
		add(panel);
		
		newMessageTextArea = new JTextArea(2, 25);
		conversationTextArea = new JTextArea("Bob: Hello Alice!", 25, 25);
		
		JScrollPane conversationScrollPane, newMessageScrollPane;
		newMessageScrollPane = new JScrollPane(newMessageTextArea);
		conversationScrollPane = new JScrollPane(conversationTextArea);
		
		JSplitPane splitPane = new JSplitPane(
				JSplitPane.VERTICAL_SPLIT, 
				conversationScrollPane, 
				newMessageScrollPane);
		panel.add(splitPane);
	}
}
