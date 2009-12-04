package edu.gatech.cc.CS4237.gtsecurechat.network;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Generates a session key by performing a variant on Diffie-Hellman.<br>
 * <a href="http://tools.ietf.org/html/draft-brusilovsky-pak-10">
 * Password-Authenticated Diffie-Hellman Exchange (PAK)</a>
 * 
 * @author corey
 */
public class Handshake {
	
	/**
	 * Identies of Alice and Bob.
	 */
	private String alice, bob;
	
	/**
	 * Secret shared between Alice and Bob used to negotiate a session key.
	 */
	private char[] pass;
	
	/**
	 * Used in the calculation of various hash functions.
	 * z = (Alice|Bob|Password)
	 */
	private byte[] z;
	
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
		"FFFFFFFF" + "FFFFFFFF",
		16);
	
	/**
	 * A very commonly used constant for the hash functions. 2^128
	 */
	private final BigInteger exp2_128 = 
		new BigInteger("2").mod(new BigInteger("128"));

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
		
		z = new byte[this.alice.length() + this.bob.length() + pass.length];
		int i = 0;
		for (int j = 0; j < alice.length(); j++) {
			z[i] = (byte) alice.charAt(j);
			i++;
		}
		for (int j = 0; j < bob.length(); j++) {
			z[i] = (byte) bob.charAt(j);
			i++;
		}
		for (int j = 0; j < pass.length; j++) {
			z[i] = (byte) pass[j];
		}
	}
	
	/**
	 * This method should only be called by the initiator of the handshake.
	 * Initially, Alice selects a secret random exponent Ra and computes g^Ra;
     * Bob selects a secret random exponent Rb and computes g^Rb.
     * For efficiency purposes, short exponents could be used for Ra and Rb
     * provided they have a certain minimum size.  Then:
     * - A --> B: {A, X = H1(A|B|PW)*(g^Ra)
     * 
	 * @return Alice's message to send to Bob.
	 * @throws Exception 
	 */
	public byte[] m1() throws Exception {
		byte[] retBytes;
		BigInteger X;
		int i;
		
		// calculate g^Ra mod p
		expG_Ra = g.modPow(rand, p);
		
		// return (A|H1(z)*(g^Ra))
		retBytes = new byte[alice.length() + 128];
		
		for (i = 0; i < alice.length(); i++) {
			retBytes[i] = (byte)alice.charAt(i);
		}
		
		// H1(z)*(g^Ra) will be 1024 bits or 128 Bytes
		X = H1().multiply(expG_Ra).mod(p);
		for (byte b : bigIntToByteArray(X, 128)) {
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
		BigInteger S1;
		BigInteger tempInt;
		
		// bob's calcluates g^Rb
		expG_Rb = g.modPow(rand, p);
		
		// extract Q from the message, Q should equal X
		tempBytes = new byte[128];
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
		tempInt = H1();
		expG_Ra = Q.multiply(tempInt.modInverse(p)).mod(p);
		
		// Y = H2(A|B|PW)*(g^Rb)
		Y = H2().multiply(expG_Rb).mod(p);
		
		// S1 = H3(A|B|PW|Xab|g^Rb|(Xab)^Rb) where Xab is recovered value g^Ra
		tempBytes = new byte[alice.length() + // number of chars in alice
		                     bob.length() +   // number of chars in bob
		                     pass.length +    // number of chars in password
		                     128 +  // number of bytes in Xab, always 128
		                     128 +  // number of bytes in g^Rb mod p
		                     128];  // number of bytes in (Xab)^Rb mod p
		i = 0;
		// A
		for (byte b : alice.getBytes()) {
			tempBytes[i] = b;
			i++;
		}
		// B
		for (byte b : bob.getBytes()) {
			tempBytes[i] = b;
			i++;
		}
		// PW
		for (char c : pass) {
			tempBytes[i] = (byte) c;
			i++;
		}
		// Xab 128 bytes
		for (byte b : bigIntToByteArray(expG_Ra, 128)) {
			tempBytes[i] = b;
			i++;
		}
		// g^Rb 128 bytes
		for (byte b : bigIntToByteArray(expG_Rb, 128)) {
			tempBytes[i] = b;
			i++;
		}
		// (Xab)^Rb 128 bytes
		for (byte b : bigIntToByteArray(expG_Rb.modPow(rand, p), 128)) {
			tempBytes[i] = b;
			i++;
		}
		S1 = H3(tempBytes);
		
		// B --> A: {Y, S1} (Y = 1024bits + S1 = 128bits) = 1152bits or 144Bytes
		retBytes = new byte[144];
		i = 0;
		for (byte b : bigIntToByteArray(Y, 128)) {
			retBytes[i] = b;
			i++;
		}
		for (byte b : bigIntToByteArray(S1, 16)) {
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
		byte[] retBytes;
		byte[] tempBytes;
		int i;
		BigInteger Y;
		BigInteger S1calc, S1recv;
		BigInteger S2;
		
		// Y will be the first 1024 bits, or 128 bytes
		tempBytes = new byte[128];
		i = 0;
		for (int j = 0; j < tempBytes.length; j++) {
			tempBytes[j] = message[i];
			i++;
		}
		Y = new BigInteger(tempBytes);
		
		// S1 received will be the remaining 128 bits or 16 bytes
		tempBytes = new byte[16];
		for (int j = 0; j < tempBytes.length; j++) {
			tempBytes[j] = message[i];
			i++;
		}
		S1recv = new BigInteger(tempBytes);
		
		// Bob can't just send us a 0
		if (Y.compareTo(new BigInteger("0")) == 0) {
			throw new Exception("Receive a value of 0");
		}
		
		// Y / H2(z) = Yba, or g^Rb
		// a/b always means a * x (mod p), where x is the multiplicative inverse
        // of b modulo p
		expG_Rb = Y.multiply(H2().modInverse(p)).mod(p);
		
		// S1' = H3(A|B|PW|g^Ra|Yba|(Yba)^Ra) where Yba is recovered value g^Rb
		tempBytes = new byte[alice.length() + // number of chars in Alice
		                     bob.length() +   // number of chars in Bob
		                     pass.length +    // number of chars in password
		                     128 +  // number of bytes in g^Ra mod p, always 128
		                     128 +  // number of bytes in Yba
		                     128];  // number of bytes in (Yba)^Ra mod p
		i = 0;
		// A
		for (byte b : alice.getBytes()) {
			tempBytes[i] = b;
			i++;
		}
		// B
		for (byte b : bob.getBytes()) {
			tempBytes[i] = b;
			i++;
		}
		// PW
		for (char c : pass) {
			tempBytes[i] = (byte) c;
			i++;
		}
		// g^Ra 128 bytes
		for (byte b : bigIntToByteArray(expG_Ra, 128)) {
			tempBytes[i] = b;
			i++;
		}
		// Yba 128 bytes
		for (byte b : bigIntToByteArray(expG_Rb, 128)) {
			tempBytes[i] = b;
			i++;
		}
		// (Yba)^Ra 128 bytes
		for (byte b : bigIntToByteArray(expG_Rb.modPow(rand, p), 128)) {
			tempBytes[i] = b;
			i++;
		}
		S1calc = H3(tempBytes);
		
		// authenticate Bob by checking whether S1' equals the received S1
		if (S1recv.compareTo(S1calc) != 0) {
			throw new Exception("Received bad handshake");
		}
		
		// if authenticated, then K = H5(A|B|PW|g^Ra|Yba|(Yba)^Ra)
		K = bigIntToByteArray(H5(tempBytes), 16);
		
		// - A --> B:  S2 = H4(A|B|PW|g^Ra|Yba|(Yba)^Ra)
		S2 = H4(tempBytes);
		retBytes = bigIntToByteArray(S2, 16);
		return retBytes;
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
		byte[] tempBytes;
		int i;
		BigInteger S2calc, S2recv;
		
		// The entire message should have been S2 which is 128 bits or 16 bytes
		S2recv = new BigInteger(message);
		
		// Compute S2' = H4(A|B|PW|Xab|g^Rb|(Xab)^Rb)
		tempBytes = new byte[alice.length() + // number of chars in Alice
		                     bob.length() +   // number of chars in Bob
		                     pass.length +    // number of chars in password
		                     128 +  // number of bytes in g^Ra mod p, always 128
		                     128 +  // number of bytes in Yba
		                     128];  // number of bytes in (Yba)^Ra mod p
		i = 0;
		// A
		for (byte b : alice.getBytes()) {
			tempBytes[i] = b;
			i++;
		}
		// B
		for (byte b : bob.getBytes()) {
			tempBytes[i] = b;
			i++;
		}
		// PW
		for (char c : pass) {
			tempBytes[i] = (byte) c;
			i++;
		}
		// Xab 128 bytes
		for (byte b : bigIntToByteArray(expG_Ra, 128)) {
			tempBytes[i] = b;
			i++;
		}
		// g^Rb 128 bytes
		for (byte b : bigIntToByteArray(expG_Rb, 128)) {
			tempBytes[i] = b;
			i++;
		}
		// (Xab)^Rb 128 bytes
		for (byte b : bigIntToByteArray(expG_Rb.modPow(rand, p), 128)) {
			tempBytes[i] = b;
			i++;
		}
		S2calc = H4(tempBytes);
		
		// authenticate Alice by checking whether S2' equals the received S2
		if (S2recv.compareTo(S2calc) != 0) {
			throw new Exception("Received bad handshake");
		}
		
		// if authenticated then sets K = H5(A|B|PW|Xab|g^Rb|(Xab)^Rb)
		K = bigIntToByteArray(H5(tempBytes), 16);
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
	private BigInteger H1() throws Exception {
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
	 * @throws NoSuchAlgorithmException
	 */
	private BigInteger H2() throws Exception {
		return H1_2(2);
	}
	
	/**
	 * 128 bit hash function.
	 * @return
	 * @throws Exception
	 */
	private BigInteger H3(byte[] arg) throws Exception {
		return H3_5(3, arg);
	}
	
	/**
	 * 128 bit hash function.
	 * @return
	 * @throws Exception
	 */
	private BigInteger H4(byte[] arg) throws Exception {
		return H3_5(4, arg);
	}
	
	/**
	 * 128 bit hash function.
	 * @return
	 * @throws Exception
	 */
	private BigInteger H5(byte[] arg) throws Exception {
		return H3_5(5, arg);
	}
	
	/**
	 * Since the only difference between H1 and H2 is one byte in the 
	 * hashed value, we will do all the actual work here.
	 * @param index 1 or 2 depending on if called from H1 or H2
	 * @return the value of Hi(z) where i is either 1 or 2
	 * @throws Exception 
	 */
	private BigInteger H1_2(int index) throws Exception {
		byte[] u;
		byte[] tempBytes;
		byte[] retBytes;
		BigInteger tempInt;
		MessageDigest sha = null;
		
		// sanity check
		if (index != 1 && index != 2) {
			throw new Exception("Value for index can only be 1 or 2");
		}
		
		// we will be returning a 1152-bit value, or 144 Bytes
		retBytes = new byte[144];
		
		// we are taking the hash of (32-bit int|32-bit int|z)
		u = new byte[z.length + 8];
		tempBytes = intToByteArray(index);
		u[0] = tempBytes[0];
		u[1] = tempBytes[1];
		u[2] = tempBytes[2];
		u[3] = tempBytes[3];
		for (int i = 0; i < z.length; i++) {
			u[i+8] = z[i];
		}
		
		// we will be using SHA-1
		try {
			sha = MessageDigest.getInstance("SHA-1");
		} catch (NoSuchAlgorithmException e) {
			// this shouldn't ever happen, but just in case...
			throw new Exception(e);
		}
		
		// We take 9 hashes in all. Each time, we take 128 bits, or 16 Bytes.
		for (byte i = 0; i < 9; i++) {
			tempBytes = intToByteArray(i);
			u[4] = tempBytes[0];
			u[5] = tempBytes[1];
			u[6] = tempBytes[2];
			u[7] = tempBytes[3];
			tempBytes = sha.digest(u);
			tempInt = new BigInteger(tempBytes).mod(exp2_128);
			
			int j = 0;
			for (byte b : bigIntToByteArray(tempInt, 16)) {
				retBytes[16 * i + j] = b;
				j++;
			}
		}
		
		// Just in case, make sure to clear the stored password from memory.
		for (int i = 0; i < u.length; i++) {
			u[i] = 0;
		}
		tempInt = new BigInteger(retBytes);
		
		// We cannot return 0
		if (tempInt.compareTo(new BigInteger("0")) == 0) {
			throw new Exception("You must pick another password.");
		} else {
			return tempInt;
		}
	}
	
	/**
	 * Since the only difference between H3, H4, and H5 is one byte in the 
	 * hashed value, we will do all the actual work here.
	 * @param i 3, 4, or 5 depending on if called from H3, H4, or H5
	 * @return the value of Hi(z) where i is either 3, 4, or 5
	 * @throws Exception 
	 */
	private BigInteger H3_5(int index, byte[] arg) throws Exception {
		byte[] u;
		byte[] tempBytes;
		byte[] retBytes;
		BigInteger tempInt;
		MessageDigest sha = null;
		
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
		
		// we will be using SHA-1
		try {
			sha = MessageDigest.getInstance("SHA-1");
		} catch (NoSuchAlgorithmException e) {
			// this shouldn't ever happen, but just in case...
			throw new Exception(e);
		}
		
		// Take the hash function
		tempBytes = sha.digest(u);
		tempInt = new BigInteger(tempBytes).mod(exp2_128);
		
		// we will be returning 128-bits or 16 bytes
		retBytes = bigIntToByteArray(tempInt, 16);
		
		// Just in case, make sure to clear the stored password from memory.
		for (int i = 0; i < u.length; i++) {
			u[i] = 0;
		}
		tempInt = new BigInteger(retBytes);
		
		// We cannot return 0
		if (tempInt.compareTo(new BigInteger("0")) == 0) {
			throw new Exception("You must pick another password.");
		} else {
			return tempInt;
		}
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
		for (int i = 0; i < z.length; i++) {
			z[i] = 0;
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
			i = 0;
			for (int j = arrLen - numBytes; j < arrLen; j++) {
				ret[i] = arr[j];
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
}























