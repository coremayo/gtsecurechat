package edu.gatech.cc.CS4237.gtsecurechat;

import java.math.BigInteger;

public class IDEABlockCipher implements IBlockCipher {

	private static int[] decryptionIndexes = {48, 49, 50, 51, 46, 47, 42, 43, 44, 45, 40, 41, 36, 37, 38, 39,  34, 35, 30, 31, 32, 33, 28, 29, 24, 25, 26, 27, 22, 23, 18, 19, 20, 21, 16, 17, 12, 13, 14, 15, 10, 11, 6, 7, 8, 9, 4, 5, 0 ,1, 2, 3};
	
	private byte[] encryptionExpansions = new byte[104];
	private byte[] decryptionExpansions = new byte[104];
	
	@Override
	public int blockSize() { return 64; }

	@Override
	public int keySize() { return 128; }

	public void initialize(byte[] key) {
		if ((key.length * 8) % this.keySize() != 0) {
			throw new IllegalArgumentException(String.format("Key size in bits must be a multiple of %d.", this.keySize()));
		}
		expandEncryptionKey(key);
		expandDecryptionKey(key);
	}

	private void expandEncryptionKey(byte[] key) {
		for (int start = 0, index = 0; index < 104; start += 25) {
			for (int i = 0; i < 16 && index < 104; i++, index++) {
				int startIndex = (start + (i*8)) % 128;
				int firstIndex = (startIndex / 8) % 16;
				int secondIndex = ((startIndex / 8) + 1) % 16;
				int byteIndex = startIndex % 8;
				
				encryptionExpansions[index] = (byte)((0x000000FF & (key[firstIndex] << byteIndex)) | ((0x000000FF & key[secondIndex]) >> (8-byteIndex)));
			}
		}
	}

	private void expandDecryptionKey(byte[] key) {
		for (int i = 0; i < 52; i++) {
			if (i % 6 == 0 || i % 6 == 3) {
				byte firstByte = encryptionExpansions[decryptionIndexes[i]*2];
				byte secondByte = encryptionExpansions[decryptionIndexes[i]*2 + 1];
				
				int byteValue = bytesToInt(firstByte, secondByte);
				int result = ((new BigInteger(Integer.toString(byteValue))).modInverse(new BigInteger("65537"))).intValue();
				decryptionExpansions[i*2] = (byte)((0xFF00 & result) >>> 8);
				decryptionExpansions[i*2+1] = (byte)(0xFF & result);
			} else if (i % 6 == 1) {
				byte firstByte = encryptionExpansions[decryptionIndexes[i+1]*2];
				byte secondByte = encryptionExpansions[decryptionIndexes[i+1]*2 + 1];
				
				int result = 65536-bytesToInt(firstByte, secondByte);
				decryptionExpansions[i*2] = (byte)((0xFF00 & result) >>> 8);
				decryptionExpansions[i*2+1] = (byte)(0xFF & result);
			} else if (i % 6 == 2) {
				byte firstByte = encryptionExpansions[decryptionIndexes[i-1]*2];
				byte secondByte = encryptionExpansions[decryptionIndexes[i-1]*2 + 1];
				
				int result = 65536-bytesToInt(firstByte, secondByte);
				decryptionExpansions[i*2] = (byte)((0xFF00 & result) >>> 8);
				decryptionExpansions[i*2+1] = (byte)(0xFF & result);				
			} else {
				decryptionExpansions[i*2] = encryptionExpansions[decryptionIndexes[i]*2];
				decryptionExpansions[i*2+1] = encryptionExpansions[decryptionIndexes[i]*2 + 1];
			}
		}
	}

	@Override
	public byte[] encrypt(byte[] input) {
		return dualCrypto(input, encryptionExpansions);
	}
	
	@Override
	public byte[] decrypt(byte[] input) {
		return dualCrypto(input, decryptionExpansions);
	}

	private byte[] dualCrypto(byte[] input, byte[] keyExpansions) {
		byte[] roundIn = input;
		
		for (int i = 0; i < 8; i++) {
			roundIn = oddRound(roundIn, keyExpansions, i*12);
			roundIn = evenRound(roundIn, keyExpansions, i*12+8);
		}
		
		return oddRound(roundIn, keyExpansions, 96);
	}
	
	private byte[] evenRound(byte[] data, byte[] keyExpansions, int keyIndex) {
		if (data.length != 8) {
			throw new IllegalArgumentException("Even round data must be 64 bytes long.");
		}

		int Xa = bytesToInt(data[0], data[1]);
		int Xb = bytesToInt(data[2], data[3]);
		int Xc = bytesToInt(data[4], data[5]);
		int Xd = bytesToInt(data[6], data[7]);
		int Ke = bytesToInt(keyExpansions[keyIndex + 0], keyExpansions[keyIndex + 1]);
		int Kf = bytesToInt(keyExpansions[keyIndex + 2], keyExpansions[keyIndex + 3]);
		
		int Yin = Xa ^ Xb;
		int Zin = Xc ^ Xd;
		int Yout = mult(add(mult(Ke,Yin),Zin),Kf);
		int Zout = add(mult(Ke,Yin),Yout);
		
		int Oa, Ob, Oc, Od;
		
		Oa = Xa ^ Yout;
		Ob = Xb ^ Yout;
		Oc = Xc ^ Zout;
		Od = Xd ^ Zout;
		
		byte[] ret = new byte[8];
		
		ret[0] = (byte)((0xFF00 & Oa) >>> 8);
		ret[1] = (byte)(0xFF & Oa);
		ret[2] = (byte)((0xFF00 & Ob) >>> 8);
		ret[3] = (byte)(0xFF & Ob);
		ret[4] = (byte)((0xFF00 & Oc) >>> 8);
		ret[5] = (byte)(0xFF & Oc);
		ret[6] = (byte)((0xFF00 & Od) >>> 8);
		ret[7] = (byte)(0xFF & Od);

		return ret;
	}
	
	private byte[] oddRound(byte[] data, byte[] keyExpansions, int keyIndex) {
		if (data.length != 8) {
			throw new IllegalArgumentException("Odd round data must be 64 bytes long.");
		}
		
		int Xa = bytesToInt(data[0], data[1]);
		int Xb = bytesToInt(data[2], data[3]);
		int Xc = bytesToInt(data[4], data[5]);
		int Xd = bytesToInt(data[6], data[7]);
		int Ka = bytesToInt(keyExpansions[keyIndex + 0], keyExpansions[keyIndex + 1]);
		int Kb = bytesToInt(keyExpansions[keyIndex + 2], keyExpansions[keyIndex + 3]);
		int Kc = bytesToInt(keyExpansions[keyIndex + 4], keyExpansions[keyIndex + 5]);
		int Kd = bytesToInt(keyExpansions[keyIndex + 6], keyExpansions[keyIndex + 7]);
		
		int Oa, Ob, Oc, Od;
		Oa = mult(Xa, Ka);
		Ob = add(Xc, Kc);
		Oc = add(Xb, Kb);
		Od = mult(Xd, Kd);
		
		byte[] ret = new byte[8];
		
		ret[0] = (byte)((0xFF00 & Oa) >>> 8);
		ret[1] = (byte)(0xFF & Oa);
		ret[2] = (byte)((0xFF00 & Ob) >>> 8);
		ret[3] = (byte)(0xFF & Ob);
		ret[4] = (byte)((0xFF00 & Oc) >>> 8);
		ret[5] = (byte)(0xFF & Oc);
		ret[6] = (byte)((0xFF00 & Od) >>> 8);
		ret[7] = (byte)(0xFF & Od);
		
		return ret;
	}
	
	private int mult(long first, long second) {
		return (int)((first * second) % 65537);
	}
	
	private int add(int first, int second) {
		return (first + second) % 65536;
	}
	

	private int bytesToInt(byte first, byte second) {
		int ret = 0;
		ret += ((0x000000FF & first) << 8);
		ret += (int)(0x000000FF & second);
		return ret;
	}

}
