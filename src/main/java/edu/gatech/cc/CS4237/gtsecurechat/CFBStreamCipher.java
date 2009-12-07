package edu.gatech.cc.CS4237.gtsecurechat;

public class CFBStreamCipher implements IStreamCipher {

	private byte[] key = null;
	private IBlockCipher cipher = null;
	
	public CFBStreamCipher(IBlockCipher cipher) {
		if ((cipher.blockSize() % 8) != 0) {
			throw new IllegalArgumentException("Cipher block size in bits must be a multiple of 8");
		}
		this.cipher = cipher;
	}

	@Override
	public String decrypt(final byte[] cipherText, final byte[] IV) {
		if (IV.length * 8 != cipher.blockSize()) {
			throw new IllegalArgumentException(String.format("IV size in bits must be a multiple of %d.", cipher.blockSize()));
		}
		if (key == null) {
			throw new IllegalStateException("Stream cipher has not been initialized with a key");
		}
		
		int numOfBlocks = (cipherText.length * 8) / cipher.blockSize();
		if ((cipherText.length * 8) % cipher.blockSize() != 0) numOfBlocks++;
		
		byte[] plain = new byte[cipherText.length];
		
		byte[] input = IV.clone();
		for (int i = 0; i < numOfBlocks; i++) {
			byte[] output = cipher.encrypt(input);
			for (int j = 0; j < cipher.blockSize() / 8; j++) {
				int index = (i*cipher.blockSize() / 8) + j;
				if (index < cipherText.length) {
					plain[index] = (byte)(output[j] ^ cipherText[index]);
					input[j] = cipherText[index];
				}
			}
		}

		return new String(plain);
	}

	@Override
	public byte[] encrypt(final String plain, final byte[] IV) {
		if (IV.length * 8 != cipher.blockSize()) {
			throw new IllegalArgumentException(String.format("IV size in bits must be a multiple of %d.", cipher.blockSize()));
		}
		if (key == null) {
			throw new IllegalStateException("Stream cipher has not been initialized with a key");
		}

		int numOfBlocks = (plain.length() * 8) / cipher.blockSize();
		if ((plain.length() * 8) % cipher.blockSize() != 0) numOfBlocks++;

		byte[] plainText = plain.getBytes();

		byte[] cipherText = new byte[plainText.length];

		byte[] input = IV.clone();
		for (int i = 0; i < numOfBlocks; i++) {
			byte[] output = cipher.encrypt(input);
			for (int j = 0; j < cipher.blockSize() / 8; j++) {
				int index = (i*cipher.blockSize() / 8) + j;
				if (index < plainText.length) {
					byte b = (byte)(output[j] ^ plainText[index]);
					input[j] = b;
					cipherText[index] = b;
				}
			}
		}

		return cipherText;
	}

	@Override
	public void initialize(byte[] key) {
		if ((key.length * 8) % cipher.keySize() != 0) {
			throw new IllegalArgumentException(String.format("Key size in bits must be a multiple of %d.", cipher.keySize()));
		}
		this.key = key;
		this.cipher.initialize(key);
	}

}
