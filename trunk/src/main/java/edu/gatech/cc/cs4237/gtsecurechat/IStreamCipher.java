package edu.gatech.cc.cs4237.gtsecurechat;

public interface IStreamCipher {

	void initialize(byte[] key);
	byte[] encrypt(String plain, byte[] IV);
	String decrypt(byte[] cipher, byte[] IV);
	
}
