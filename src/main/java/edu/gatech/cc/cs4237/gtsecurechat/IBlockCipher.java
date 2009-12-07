package edu.gatech.cc.cs4237.gtsecurechat;

public interface IBlockCipher {

	int keySize();
	int blockSize();

	void initialize(byte[] key);

	byte[] encrypt(byte[] data);
	byte[] decrypt(byte[] data);

}
