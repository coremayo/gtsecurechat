package edu.gatech.cc.cs4237.gtsecurechat;

public class InvalidPasswordException extends Exception {

	private static final long serialVersionUID = 3449064736325676143L;
	
	public InvalidPasswordException(String message) {
		super(message);
	}

	public InvalidPasswordException(Throwable ex) {
		super(ex);
	}
	
}
