package edu.gatech.cc.CS4237.gtsecurechat;

public class DummyEncryption implements IStreamCipher {

	@Override
	public String decrypt(byte[] cipher, byte[] IV) {
		return new String(cipher);
	}

	@Override
	public byte[] encrypt(String plain, byte[] IV) {
		return plain.getBytes();
	}

	@Override
	public void initialize(byte[] key) {
	}

}
