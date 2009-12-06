package edu.gatech.cc.CS4237.gtsecurechat;

import java.nio.ByteBuffer;

public class IDEABlockCipher implements IBlockCipher {

	private static int[] decryptionIndexes = {96,97,98,99,100,101,102,103,92,93,94,95,84,85,86,87,88,89,90,91,80,81,82,83,72,73,74,75,76,77,78,79,68,69,70,71,60,61,62,63,64,65,66,67,56,57,58,59,48,49,50,51,52,53,54,55,44,45,46,47,36,37,38,39,40,41,42,43,32,33,34,35,24,25,26,27,28,29,30,31,20,21,22,23,12,13,14,15,16,17,18,19,8,9,10,11,0,1,2,3,4,5,6,7};
	
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
				int firstIndex = startIndex / 8;
				int secondIndex = (startIndex / 8) + 1;
				encryptionExpansions[index] = (byte)((key[firstIndex] & (0>>(8-(startIndex%8)))) | (key[secondIndex] & (0<<(startIndex%8))));
			}
		}
	}

	private void expandDecryptionKey(byte[] key) {
		for (int i = 0; i < 54; i++) {
			byte firstByte = encryptionExpansions[decryptionIndexes[i*2]];
			byte secondByte = encryptionExpansions[decryptionIndexes[i*2+1]];
			if (i % 6 == 0 || i % 6 == 3) {
				int result = multInverse(bytesToInt(firstByte, secondByte));
				decryptionExpansions[i*2] = (byte)((0xFF00 & result) >>> 8);
				decryptionExpansions[i*2+1] = (byte)(0xFF & result);
			} else if (i % 6 == 2 || i % 6 == 3) {
				int result = -bytesToInt(firstByte, secondByte);
				decryptionExpansions[i*2] = (byte)((0xFF00 & result) >>> 8);
				decryptionExpansions[i*2+1] = (byte)(0xFF & result);
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
			roundIn = oddRound(roundIn, keyExpansions, i*2);
			roundIn = evenRound(roundIn, keyExpansions, i*2+1);
		}
		
		return oddRound(roundIn, keyExpansions, 16);
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
		
		short Oa, Ob, Oc, Od;
		
		Oa = (short)(Xa ^ Yout);
		Ob = (short)(Xb ^ Yout);
		Oc = (short)(Xc ^ Zout);
		Od = (short)(Xd ^ Zout);
		
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
		
		short Oa, Ob, Oc, Od;
		Oa = (short)mult(Xa, Ka);
		Ob = (short)add(Xc, Kc);
		Oc = (short)add(Xb, Kb);
		Od = (short)mult(Xd, Kd);
		
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
	
	private int mult(int first, int second) {
		return (first * second) % 65537;
	}
	
	private int add(int first, int second) {
		return (first + second) % 65536;
	}
	
	private int bytesToInt(byte first, byte second) {
		ByteBuffer bb = ByteBuffer.allocate(4);
		bb.put((byte)0);
		bb.put((byte)0);
		bb.put(first);
		bb.put(second);
		
		return bb.getInt();
	}
	
	private int multInverse(int bytesToInt) {
		int a = 65537;
		int b = bytesToInt;
		int rem = a % b;
		
		while (rem > 0) {
			a = b;
			b = rem;
			rem = a % b;
		}
		
		return b;
	}

}
