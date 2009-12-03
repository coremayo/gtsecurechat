package edu.gatech.cc.CS4237.gtsecurechat.GUI;

import javax.swing.JFrame;

public abstract class AbstractFrame extends JFrame {

	private static final long serialVersionUID = 3112542615722479001L;

	protected GTSecureChat program;
	
	public AbstractFrame(GTSecureChat program) {
		this.program = program;
	}
}
