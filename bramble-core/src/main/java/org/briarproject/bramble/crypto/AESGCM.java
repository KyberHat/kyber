package org.briarproject.bramble.crypto;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
//import org.graalvm.compiler.nodes.java.ExceptionObjectNode;

import static org.briarproject.bramble.api.transport.TransportConstants.MAC_LENGTH;


public class AESGCM {




	/**
	 * The standard Initialization Vector (IV) length (96 bits).
	 */
	public static final int IV_BIT_LENGTH = 96;

	/**
	 * The standard authentication tag length (128 bits).
	 */
	public static final int AUTH_TAG_BIT_LENGTH = 128;

	/**
	 * Generates a random 96 bit (12 byte) Initialization Vector(IV) for use in AES-GCM encryption.
	 *
	 * <p>
	 * See draft-ietf-jose-json-web-algorithms-26, section 5.3.
	 *
	 * @param randomGen The secure random generator to use. Must be correctly initialized and not {@code null}.
	 *
	 * @return The random 96 bit IV, as 12 byte array.
	 */
	public  byte[] generateIV(final SecureRandom randomGen) {

		byte[] bytes = new byte[IV_BIT_LENGTH / 8];
		randomGen.nextBytes(bytes);
		return bytes;
	}

	public int computeInputLength(int outputLength)
	{
		try {
			KeyGenerator keyGen = KeyGenerator.getInstance("AES");
			keyGen.init(128);
			SecretKey secretKey = keyGen.generateKey();


			GCMBlockCipher cipher = createAESGCMCipher(secretKey, false,
					new byte[IV_BIT_LENGTH / 8],
					new byte[AUTH_TAG_BIT_LENGTH / 8]);

			outputLength -= IV_BIT_LENGTH / 8;
			outputLength += AUTH_TAG_BIT_LENGTH / 8;
			outputLength -= MAC_LENGTH;

			// Prepare output buffer
			int inputLength = cipher.getOutputSize(outputLength);

			return inputLength;
		}
		catch(Exception ex)
		{

			return 0;
		}

	}

	public int computeOutputLength(int inputLength)
	{
		try {
			KeyGenerator keyGen = KeyGenerator.getInstance("AES");
			keyGen.init(128);
			SecretKey secretKey = keyGen.generateKey();


			GCMBlockCipher cipher = createAESGCMCipher(secretKey, true,
					new byte[IV_BIT_LENGTH / 8],
					new byte[AUTH_TAG_BIT_LENGTH / 8]);

			// Prepare output buffer
			int outputLength = cipher.getOutputSize(inputLength);

			outputLength += IV_BIT_LENGTH / 8;
			outputLength -= AUTH_TAG_BIT_LENGTH / 8;
			outputLength += MAC_LENGTH;

			return outputLength;
		}
		catch(Exception ex)
		{

			return 0;
		}

	}

	/**
	 * Creates a new AES/GCM/NoPadding cipher.
	 *
	 * @param secretKey The AES key. Must not be {@code null}.
	 * @param forEncryption If {@code true} creates an encryption cipher, else creates a decryption cipher.
	 * @param iv The initialisation vector (IV). Must not be {@code null}.
	 * @param authData The authenticated data. Must not be {@code null}.
	 *
	 * @return The AES/GCM/NoPadding cipher.
	 */
	private  GCMBlockCipher createAESGCMCipher(final SecretKey secretKey, final boolean forEncryption,
			final byte[] iv, final byte[] authData){

		// Initialize AES cipher
		BlockCipher cipher =new AESEngine();
		//AES.createCipher(secretKey, forEncryption);
		KeyParameter keyParameter = new KeyParameter(secretKey.getEncoded());
		cipher.init(forEncryption, keyParameter);

		// Create GCM cipher with AES
		GCMBlockCipher gcm = new GCMBlockCipher(cipher);

		AEADParameters aeadParams = new AEADParameters(new KeyParameter(secretKey.getEncoded()),
				AUTH_TAG_BIT_LENGTH, iv, authData);
		gcm.init(forEncryption, aeadParams);

		return gcm;
	}



	/**
	 * Encrypts the specified plain text using AES/GCM/NoPadding.
	 *
	 * @param secretKey The AES key. Must not be {@code null}.
	 * @param plainText The plain text. Must not be {@code null}.
	 * @param iv The initialization vector (IV). Must not be {@code null}.
	 * @param authData The authenticated data. Must not be {@code null}.
	 *
	 * @return The authenticated cipher text.
	 *
	 * @throws RuntimeException If encryption failed.
	 */
	public SealedBox encrypt(final SecretKey secretKey, final byte[] iv,
			final byte[] plainText, final byte[] authData) {

		// Initialise AES/GCM cipher for encryption
		GCMBlockCipher cipher = createAESGCMCipher(secretKey, true, iv, authData);

		// Prepare output buffer
		int outputLength = cipher.getOutputSize(plainText.length);
		byte[] output = new byte[outputLength];

		// Produce cipher text
		int outputOffset = cipher.processBytes(plainText, 0, plainText.length, output, 0);

		// Produce authentication tag
		try {
			outputOffset += cipher.doFinal(output, outputOffset);
		} catch (InvalidCipherTextException e) {
			throw new RuntimeException("Couldn't generate GCM authentication tag: " + e.getMessage(), e);
		}

		// Split output into cipher text and authentication tag
		int authTagLength = AUTH_TAG_BIT_LENGTH / 8;

		byte[] cipherText = new byte[outputOffset - authTagLength];
		byte[] authTag = new byte[authTagLength];

		System.arraycopy(output, 0, cipherText, 0, cipherText.length);
		System.arraycopy(output, outputOffset - authTagLength, authTag, 0, authTag.length);
		SealedBox sb= new SealedBox(cipherText, authTag,iv);

		return sb;
	}

	/**
	 * Decrypts the specified cipher text using AES/GCM/NoPadding.
	 *
	 * @param secretKey The AES key. Must not be {@code null}.
	 * @param iv The initialisation vector (IV). Must not be {@code null}.
	 * @param cipherText The cipher text. Must not be {@code null}.
	 * @param authData The authenticated data. Must not be {@code null}.
	 * @param authTag The authentication tag. Must not be {@code null}.
	 *
	 * @return The decrypted plain text.
	 *
	 * @throws RuntimeException If decryption failed.
	 */
	public  byte[] decrypt(final SecretKey secretKey, final byte[] iv, final byte[] cipherText,
			final byte[] authData, final byte[] authTag) {

		// Initialise AES/GCM cipher for decryption
		GCMBlockCipher cipher = createAESGCMCipher(secretKey, false, iv, authData);

		// Join cipher text and authentication tag to produce cipher input
		byte[] input = new byte[cipherText.length + authTag.length];

		System.arraycopy(cipherText, 0, input, 0, cipherText.length);
		System.arraycopy(authTag, 0, input, cipherText.length, authTag.length);

		int outputLength = cipher.getOutputSize(input.length);

		byte[] output = new byte[outputLength];

		// Decrypt
		int outputOffset = cipher.processBytes(input, 0, input.length, output, 0);

		// Validate authentication tag
		try {
			outputOffset += cipher.doFinal(output, outputOffset);
		} catch (InvalidCipherTextException e) {
			throw new RuntimeException("Couldn't validate GCM authentication tag: " + e.getMessage(), e);
		}
		return output;
	}

	/**
	 * Prevents public instantiation.
	 */
	//private AESGCM() {
	//}
}