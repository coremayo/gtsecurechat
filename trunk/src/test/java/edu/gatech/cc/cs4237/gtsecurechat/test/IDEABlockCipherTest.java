package edu.gatech.cc.cs4237.gtsecurechat.test;

import org.junit.Assert;
import org.junit.Test;

import edu.gatech.cc.cs4237.gtsecurechat.IDEABlockCipher;

public class IDEABlockCipherTest{

	private byte[] key = {0x73, 0x68, 0x23, 0x20, 0x40, 0x33, 0x3F, 0x48, 0x3E, 0x0D, 0x77, 0x39, 0x52, 0x7D, 0x1E, 0x00,};
	private byte[] clear = {0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x11, 0x22}; 

	@Test
	public void testEncrypt() {
		IDEABlockCipher cipher = new IDEABlockCipher();
		cipher.initialize(key);
		
		cipher.encrypt(clear);
	}
	
	@Test
	public void testDecrypt() {
		IDEABlockCipher cipher = new IDEABlockCipher();
		cipher.initialize(key);
		
		byte[] cipherText = cipher.encrypt(clear);
		byte[] output = cipher.decrypt(cipherText);
		Assert.assertArrayEquals(clear, output);
	}

}
