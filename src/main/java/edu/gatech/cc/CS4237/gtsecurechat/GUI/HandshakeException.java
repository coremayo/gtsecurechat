package edu.gatech.cc.CS4237.gtsecurechat.GUI;

public class HandshakeException extends Exception {

	private static final long serialVersionUID = -6680278330472850445L;

	public HandshakeException(String message) {
		super(message);
	}
	
	public HandshakeException(Throwable e) {
		super(e);
	}
}
