package edu.gatech.cc.CS4237.gtsecurechat.network;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Generates a session key by performing a variant on Diffie-Hellman.<br>
 * <a href="http://tools.ietf.org/html/draft-brusilovsky-pak-10">
 * Password-Authenticated Diffie-Hellman Exchange (PAK)</a>
 * 
 * @author corey
 */
public class Handshake {
	
	/**
	 * Identities of Alice and Bob. Reffered from here on out as A and B.
	 */
	private String alice, bob;
	
	/**
	 * Secret shared between Alice and Bob used to negotiate a session key.
	 */
	private char[] pass;
	
	/**
	 * Used in the calculation of various hash functions.
	 * z1 = (A|B|Password)
	 */
	private byte[] z1;
	
	/**
	 * Used in the calculation of H3, H4, and H5 hash functions.<br>
	 * For Alice, z2 = (A|B|PW|g^Ra|Yba|(Yba)^Ra)<br>
	 * For Bob, z2 = (A|B|PW|Xab|g^Rb|(Xab)^Rb)
	 */
	private byte[] z2;
	
	/**
	 * The session key that will be negotiated during the handshake.
	 */
	private byte[] K;

	/**
	 * Secret random exponent of at least 384-bits.
	 */
	private BigInteger rand;
	
	/**
	 * g^rand mod p
	 */
	private BigInteger expG_Ra, expG_Rb;
	
	/**
	 * p and g are pre-agreed upon constants. p is a large prime (1024-bits) 
	 * and g is a primitive root of p.
	 */
	private final BigInteger g = new BigInteger("00001101", 2),
	                         p = new BigInteger(
		"FFFFFFFF" + "FFFFFFFF" + "C90FDAA2" + "2168C234" + "C4C6628B" +
		"80DC1CD1" + "29024E08" + "8A67CC74" + "020BBEA6" + "3B139B22" +
		"514A0879" + "8E3404DD" + "EF9519B3" + "CD3A431B" + "302B0A6D" +
		"F25F1437" + "4FE1356D" + "6D51C245" + "E485B576" + "625E7EC6" +
		"F44C42E9" + "A637ED6B" + "0BFF5CB6" + "F406B7ED" + "EE386BFB" +
		"5A899FA5" + "AE9F2411" + "7C4B1FE6" + "49286651" + "ECE65381" +
		"FFFFFFFF" + "FFFFFFFF", 16);
	
//	/**
//	 * A very commonly used constant for the hash functions. 2^128
//	 */
//	private final BigInteger exp2_128 = 
//		new BigInteger("2").mod(new BigInteger("128"));
	
	/**
	 * Used for hashing stuff.
	 */
	private MessageDigest sha;

	/**
	 * 
	 * @param alice
	 * @param bob
	 * @param pass
	 */
	public Handshake(final String alice, 
			         final String bob, 
			         final char[] pass) {
		
		this.alice = alice;
		this.bob = bob;
		this.pass = pass;
		
		// generate a sufficiently large prime for the exponent
		rand = BigInteger.probablePrime(384, new SecureRandom());
		
		z1 = new byte[this.alice.length() + this.bob.length() + pass.length];
		int i = 0;
		for (int j = 0; j < alice.length(); j++) {
			z1[i] = (byte) alice.charAt(j);
			i++;
		}
		for (int j = 0; j < bob.length(); j++) {
			z1[i] = (byte) bob.charAt(j);
			i++;
		}
		for (int j = 0; j < pass.length; j++) {
			z1[i] = (byte) pass[j];
		}
		
		// we will be using SHA-1
		try {
			sha = MessageDigest.getInstance("SHA-1");
		} catch (NoSuchAlgorithmException e) {
			// this shouldn't ever happen, but just in case...
			e.printStackTrace();
		}
	}
	
	/**
	 * This method should only be called by the initiator of the handshake.
	 * Initially, Alice selects a secret random exponent Ra and computes g^Ra;
     * Bob selects a secret random exponent Rb and computes g^Rb.
     * For efficiency purposes, short exponents could be used for Ra and Rb
     * provided they have a certain minimum size.  Then:
     * - A --> B: {A, X = H1(A|B|PW)*(g^Ra)}
     * 
	 * @return Alice's message to send to Bob.
	 * @throws Exception 
	 */
	public byte[] m1() throws Exception {
		byte[] retBytes;
		byte[] tempBytes;
		BigInteger tempInt;
		BigInteger X;
		int i;
		
		// calculate g^Ra mod p
		expG_Ra = g.modPow(rand, p);
		
		tempBytes = H1();
		tempInt = new BigInteger(tempBytes);
		
		// return (A|H1(z)*(g^Ra))
		retBytes = new byte[alice.length() + 129];
		
		for (i = 0; i < alice.length(); i++) {
			retBytes[i] = (byte)alice.charAt(i);
		}
		
		// X = H1(z)*(g^Ra) will be 1024 bits or 128 Bytes
		X = (tempInt.multiply(expG_Ra)).mod(p);
		tempBytes = bigIntToByteArray(X, 129);
		for (byte b : tempBytes) {
			retBytes[i] = b;
			i++;
		}
		return retBytes;
	}
	
	/**
	 * This method should only be called by the recipient of the handshake and 
	 * only after receiving the first message from the initiator.
	 * Bob receives Q (presumably Q = X), verifies that Q != 0 (if Q = 0,
	 * Bob aborts the procedure);
	 * divides Q by H1(A|B|PW) to get Xab, the recovered value of g^Ra;
	 * - B --> A:  {Y = H2(A|B|PW)*(g^Rb), S1 = H3(A|B|PW|Xab|g^Rb|(Xab)^Rb)}
	 * 
	 * @return Bob's message to send to Alice.
	 * @throws Exception 
	 */
	public byte[] m2(byte[] message) throws Exception {
		byte[] retBytes;
		byte[] tempBytes;
		int i;
		BigInteger Q;
		BigInteger Y;
		byte[] S1;
		BigInteger h2;
		BigInteger tempInt;
		
		// bob's calcluates g^Rb
		expG_Rb = g.modPow(rand, p);
		
		// check to make sure the message is the right length
		if (message.length != alice.length() + 129) {
			throw new Exception("Received invalid handshake");
		}
		
		// extract Q from the message, Q should equal X
		tempBytes = new byte[129];
		for (i = 0; i < tempBytes.length; i++) {
			tempBytes[i] = message[i + alice.length()];
		}
		Q = new BigInteger(tempBytes);

		// Alice can't just send us a 0
		if (Q.compareTo(new BigInteger("0")) == 0) {
			throw new Exception("Receive a value of 0");
		}
		
		// we can now recover g^Ra = Q / H1(A|B|PW)
		// a/b always means a * x (mod p), where x is the multiplicative inverse
        // of b modulo p
		tempBytes = H1();
		tempInt = new BigInteger(tempBytes);
		expG_Ra = Q.multiply(tempInt.modInverse(p)).mod(p);
		
		// Y = H2(A|B|PW)*(g^Rb)
		h2 = new BigInteger(H2());
		Y = h2.multiply(expG_Rb).mod(p);
		
		// S1 = H3(A|B|PW|Xab|g^Rb|(Xab)^Rb) where Xab is recovered value g^Ra
		z2 = new byte[alice.length() + // number of chars in alice
		                     bob.length() +   // number of chars in bob
		                     pass.length +    // number of chars in password
		                     129 +  // number of bytes in Xab, always 128
		                     129 +  // number of bytes in g^Rb mod p
		                     129];  // number of bytes in (Xab)^Rb mod p
		i = 0;
		// A
		for (byte b : alice.getBytes()) {
			z2[i] = b;
			i++;
		}
		// B
		for (byte b : bob.getBytes()) {
			z2[i] = b;
			i++;
		}
		// PW
		for (char c : pass) {
			z2[i] = (byte) c;
			i++;
		}
		// Xab 128 bytes
		for (byte b : bigIntToByteArray(expG_Ra, 129)) {
			z2[i] = b;
			i++;
		}
		// g^Rb 128 bytes
		for (byte b : bigIntToByteArray(expG_Rb, 129)) {
			z2[i] = b;
			i++;
		}
		// (Xab)^Rb 128 bytes
		for (byte b : bigIntToByteArray(expG_Ra.modPow(rand, p), 129)) {
			z2[i] = b;
			i++;
		}
		S1 = H3(z2);
		
		// B --> A: {Y, S1} (Y = 1024bits + S1 = 128bits) = 1152bits or 144Bytes
		retBytes = new byte[129 + S1.length];
		i = 0;
		for (byte b : bigIntToByteArray(Y, 129)) {
			retBytes[i] = b;
			i++;
		}
		for (byte b : S1) {
			retBytes[i] = b;
			i++;
		}
		
		return retBytes;
	}
	
	/**
	 * This method should only be called by the initiator of the handshake and 
	 * only after they have received a response from the initial message.
	 * Alice verifies that Y != 0;
	 * divides Y by H2(A|B|PW) to get Yba, the recovered value of g^Rb
	 * and computes S1' = H3(A|B|PW|g^Ra|Yba|(Yba)^Ra);
	 * authenticates Bob by checking whether S1' equals the received S1;
	 * if authenticated, then sets key K = H5(A|B|PW|g^Ra|Yba|(Yba)^Ra)
	 * - A --> B:  S2 = H4(A|B|PW|g^Ra|Yba|(Yba)^Ra)
	 * 
	 * @return
	 * @throws Exception
	 */
	public byte[] m3(byte[] message) throws Exception {
		byte[] tempBytes;
		byte[] S1calc, S1recv;
		byte[] S2;
		int i;
		BigInteger Y;
		
		// Y will be the first 1024 bits, or 128 bytes
		tempBytes = new byte[129];
		i = 0;
		for (int j = 0; j < tempBytes.length; j++) {
			tempBytes[j] = message[i];
			i++;
		}
		Y = new BigInteger(tempBytes);
		
		// S1 received will be the remaining 128 bits or 16 bytes
		S1recv = new byte[16];
		for (int j = 0; j < S1recv.length; j++) {
			S1recv[j] = message[i];
			i++;
		}
		
		// Bob can't just send us a 0
		if (Y.compareTo(new BigInteger("0")) == 0) {
			throw new Exception("Received a value of 0");
		}
		
		// Y / H2(z) = Yba, or g^Rb
		// a/b always means a * x (mod p), where x is the multiplicative inverse
        // of b modulo p
		expG_Rb = Y.multiply(new BigInteger(H2()).modInverse(p)).mod(p);
		
		// S1' = H3(A|B|PW|g^Ra|Yba|(Yba)^Ra) where Yba is recovered value g^Rb
		z2 = new byte[alice.length() + // number of chars in Alice
		                     bob.length() +   // number of chars in Bob
		                     pass.length +    // number of chars in password
		                     129 +  // number of bytes in g^Ra mod p, always 128
		                     129 +  // number of bytes in Yba
		                     129];  // number of bytes in (Yba)^Ra mod p
		i = 0;
		// A
		for (byte b : alice.getBytes()) {
			z2[i] = b;
			i++;
		}
		// B
		for (byte b : bob.getBytes()) {
			z2[i] = b;
			i++;
		}
		// PW
		for (char c : pass) {
			z2[i] = (byte) c;
			i++;
		}
		// g^Ra 128 bytes
		for (byte b : bigIntToByteArray(expG_Ra, 129)) {
			z2[i] = b;
			i++;
		}
		// Yba 128 bytes
		for (byte b : bigIntToByteArray(expG_Rb, 129)) {
			z2[i] = b;
			i++;
		}
		// (Yba)^Ra 128 bytes
		for (byte b : bigIntToByteArray(expG_Rb.modPow(rand, p), 129)) {
			z2[i] = b;
			i++;
		}
		S1calc = H3(z2);
		
		// authenticate Bob by checking whether S1' equals the received S1
		if (!Arrays.equals(S1recv, S1calc)) {
			throw new Exception("Received bad handshake");
		}
		
		// if authenticated, then K = H5(A|B|PW|g^Ra|Yba|(Yba)^Ra)
		K = H5(z2);
		
		// - A --> B:  S2 = H4(A|B|PW|g^Ra|Yba|(Yba)^Ra)
		S2 = H4(z2);
//		retBytes = bigIntToByteArray(S2, 16);
		return S2;
	}
	
	/**
	 * This method should only be called by the recipient of the handshake and 
	 * only after receiving the second message from the initiator.
	 * Bob Computes S2' = H4(A|B|PW|Xab|g^Rb|(Xab)^Rb) and
	 * authenticates Alice by checking whether S2' equals the received S2;
	 * if authenticated then sets K = H5(A|B|PW|Xab|g^Rb|(Xab)^Rb)
	 * 
	 * @param message
	 * @throws Exception
	 */
	public void m4(byte[] message) throws Exception {
		byte[] S2calc, S2recv;
		
		// The entire message should have been S2 which is 128 bits or 16 bytes
		S2recv = message;
		
		// Compute S2' = H4(A|B|PW|Xab|g^Rb|(Xab)^Rb)
		S2calc = H4(z2);
		
		// authenticate Alice by checking whether S2' equals the received S2
		if (!Arrays.equals(S2recv, S2calc)) {
			throw new Exception("Received bad handshake");
		}
		
		// if authenticated then sets K = H5(A|B|PW|Xab|g^Rb|(Xab)^Rb)
		K = H5(z2);
	}
	
	/**
	 * A function used to derive the key. Returns an 1152-bit byte array 
	 * generated from a series of hash functions performed on the identies of 
	 * Alice and Bob and their secret passphrase.<br />
	 * H1(z): SHA-1(1|1|z) mod 2^128 | SHA-1(1|2|z) mod 2^128 |. . .| 
	 * SHA-1(1|9|z) mod 2^128
	 * @return
	 * @throws Exception if for some unlikely reason H1 generated a 0
	 */
	private byte[] H1() throws Exception {
		return H1_2(1);
	}
	
	/**
	 * A function used to derive the key. Returns an 1152-bit byte array 
	 * generated from a series of hash functions performed on the identies of 
	 * Alice and Bob and their secret passphrase.<br />
	 * H2(z): SHA-1(2|1|z) mod 2^128 | SHA-1(2|2|z) mod 2^128 |. . .| 
	 * SHA-1(2|9|z) mod 2^128
	 * @return
	 * @throws Exception if for some unlikely reason H2(z) generated a 0
	 */
	private byte[] H2() throws Exception {
		return H1_2(2);
	}
	
	/**
	 * 128 bit hash function.
	 * @return
	 * @throws Exception
	 */
	private byte[] H3(byte[] arg) throws Exception {
		return H3_5(3, arg);
	}
	
	/**
	 * 128 bit hash function.
	 * @return
	 * @throws Exception
	 */
	private byte[] H4(byte[] arg) throws Exception {
		return H3_5(4, arg);
	}
	
	/**
	 * 128 bit hash function.
	 * @return
	 * @throws Exception
	 */
	private byte[] H5(byte[] arg) throws Exception {
		return H3_5(5, arg);
	}
	
	/**
	 * Since the only difference between H1 and H2 is one byte in the 
	 * hashed value, we will do all the actual work here.
	 * @param index 1 or 2 depending on if called from H1 or H2
	 * @return the value of Hi(z) where i is either 1 or 2
	 * @throws Exception 
	 */
	private byte[] H1_2(int index) throws Exception {
		byte[] u;
		byte[] tempBytes;
		byte[] retBytes;
		
		// sanity check
		if (index != 1 && index != 2) {
			throw new Exception("Value for index can only be 1 or 2");
		}
		
		// we will be returning a 1152-bit value, or 144 Bytes
		retBytes = new byte[144];
		
		// we are taking the hash of (32-bit int|32-bit int|z)
		u = new byte[z1.length + 8];
		tempBytes = intToByteArray(index);
		u[0] = tempBytes[0];
		u[1] = tempBytes[1];
		u[2] = tempBytes[2];
		u[3] = tempBytes[3];
		for (int i = 0; i < z1.length; i++) {
			u[i+8] = z1[i];
		}
		
		// We take 9 hashes in all. Each time, we take 128 bits, or 16 Bytes.
		for (int i = 0; i < 9; i++) {
			tempBytes = intToByteArray(i);
			u[4] = tempBytes[0];
			u[5] = tempBytes[1];
			u[6] = tempBytes[2];
			u[7] = tempBytes[3];
			tempBytes = sha.digest(u);
			
			// SHA-1 returns 160 bits; we only want 128 (or 20 bytes/16 bytes)
			for (int j = 0; j < 16 ; j++) {
				retBytes[16 * i + j] = tempBytes[j + tempBytes.length - 16];
				j++;
			}
		}
		
		// Just in case, make sure to clear the stored password from memory.
		for (int i = 0; i < u.length; i++) {
			u[i] = 0;
		}
		
		// We cannot return 0
		if (Arrays.equals(retBytes, new byte[retBytes.length])) {
			throw new Exception("You must pick another password.");
		} else {
			return retBytes;
		}
	}
	
	/**
	 * Since the only difference between H3, H4, and H5 is one byte in the 
	 * hashed value, we will do all the actual work here. Returns 16 bytes.
	 * @param i 3, 4, or 5 depending on if called from H3, H4, or H5
	 * @return the value of Hi(z) where i is either 3, 4, or 5
	 * @throws Exception 
	 */
	private byte[] H3_5(int index, byte[] arg) throws Exception {
		byte[] u;
		byte[] tempBytes;
		byte[] retBytes;
		
		// sanity check
		if (index != 3 && index != 4 && index != 5) {
			throw new Exception("Value for index can only be 3, 4, or 5");
		}
		
		// Hi(arg) = sha(32-bit|32-bit|arg|arg) mod 2^128
		u = new byte[8 + arg.length * 2];
		tempBytes = intToByteArray(index);
		u[0] = tempBytes[0];
		u[1] = tempBytes[1];
		u[2] = tempBytes[2];
		u[3] = tempBytes[3];

		tempBytes = intToByteArray(arg.length);
		u[4] = tempBytes[0];
		u[5] = tempBytes[1];
		u[6] = tempBytes[2];
		u[7] = tempBytes[3];
		
		for (int i = 0; i < arg.length; i++) {
			u[8 + i] = arg[i];
			u[8 + i + arg.length] = arg[i];
		}
		
		// Take the hash function
		tempBytes = sha.digest(u);
		
		// SHA-1 provides 160 bits or 20 bytes
		// we will be returning 128-bits or 16 bytes
		retBytes = new byte[16];
		for (int i = 0; i < retBytes.length; i++) {
			retBytes[i] = tempBytes[i + tempBytes.length - retBytes.length];
		}
		
		// Just in case, make sure to clear the stored password from memory.
		for (int i = 0; i < u.length; i++) {
			u[i] = 0;
		}
		return retBytes;
	}
	
	
	/**
	 * Read somewhere in Java documentation that when working with passwords, 
	 * it is a good idea to store them in char arrays and set each clear the 
	 * array when done.
	 */
	public void destroy() {
		for (int i = 0; i < pass.length; i++) {
			pass[i] = 0;
		}
		for (int i = 0; i < z1.length; i++) {
			z1[i] = 0;
		}
	}

	/**
	 * Converts a 32-bit int to a byte array. 
	 * Will always return an array of length 4.
	 * @param value 32-bit integer
	 * @return byte array representation of value
	 */
	private byte[] intToByteArray(int value) {
        return new byte[] {
            (byte)(value >>> 24),
            (byte)(value >>> 16),
            (byte)(value >>> 8),
            (byte)value};
	}
	
	/**
	 * Will convert a BigInteger to a byte array of the specified length, 
	 * truncating or padding with zeroes if needed. Padding will place zeroes 
	 * in front of the most significant bits. Truncating will remove the most 
	 * significant bits.
	 * @param value Number to be converted to byte array
	 * @param numBytes Length of the returned byte array
	 * @return
	 */
	private byte[] bigIntToByteArray(BigInteger value, int numBytes) {
		byte[] ret;
		byte[] arr;
		int arrLen;
		int i;

		arr = value.toByteArray();
		arrLen = arr.length;
		if (arrLen == numBytes) {
			return arr;
		}
		
		ret = new byte[numBytes];
		
		// Do we need to pad
		if (arrLen < numBytes) {
			// yes, let's pad
			for (i = 0; i < numBytes - arrLen; i++) {
				ret[i] = 0;
			}
			for (int j = 0; j < arrLen; j++) {
				ret[i] = arr[j];
				i++;
			}
			return ret;
			
		} else {
			// no, we need to truncate
			int offset = arrLen - numBytes;
			for (int j = 0; j < numBytes; j++) {
				ret[j] = arr[j+offset];
			}
			return ret;
		}
	}
	
	/**
	 * Returns the session key that was negitated during the handshake. If the 
	 * handshake isn't finished yet, then this will return null.
	 * @return 128-bit or 16 Byte session key
	 */
	public byte[] getKey() {
		return K;
	}
	
	/**
	 * Converts a byte array into a String of hex characters.
	 * @param arr
	 * @return
	 */
	public static String byteArrayToHexString(byte[] arr) {
		StringBuffer sb = new StringBuffer(arr.length * 2);
		for (byte b : arr) {
			int a = b & 0xff;
			if (a < 16) {
				sb.append('0');
			}
			sb.append(Integer.toHexString(a));
		}
		return sb.toString();
	}
}
