package org.briarproject.bramble.crypto;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.engines.XSalsa20Engine;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.generators.Poly1305KeyGenerator;
import org.bouncycastle.crypto.macs.Poly1305;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.jcajce.provider.digest.SHA3;
import org.briarproject.bramble.api.crypto.KeyPair;
import org.briarproject.bramble.api.crypto.PrivateKey;
import org.briarproject.bramble.api.crypto.PublicKey;
import org.briarproject.bramble.api.crypto.SecretKey;
import org.briarproject.nullsafety.NotNullByDefault;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.annotation.concurrent.NotThreadSafe;
import javax.crypto.spec.SecretKeySpec;

import static org.briarproject.bramble.api.transport.TransportConstants.MAC_LENGTH;

/**
 * An authenticated cipher that uses XSalsa20 for encryption and Poly1305 for
 * authentication. It is equivalent to the C++ implementation of
 * crypto_secretbox in NaCl, and to the C implementations of crypto_secretbox
 * in NaCl and libsodium once the zero-padding has been removed.
 * <p/>
 * References:
 * <ul>
 * <li>http://nacl.cr.yp.to/secretbox.html</li>
 * <li>http://cr.yp.to/highspeed/naclcrypto-20090310.pdf</li>
 * </ul>
 */
@NotThreadSafe
@NotNullByDefault
public
class XSalsa20Poly1305AuthenticatedCipher implements AuthenticatedCipher {

	/**
	 * Length of the padding to be used to generate the Poly1305 key
	 */
	private static final int SUBKEY_LENGTH = 32;
	private static final int AUTH_TAG_BIT_LENGTH = 128;
	private static final String AUTH_TAG_STRING ="kXv9tfP4QhnyL3CV";

	private final XSalsa20Engine xSalsa20Engine;

	private final byte[] AES_masterkey=new byte[]{(byte) 0xc5,0x77 , (byte) 0xdf,0x4b ,0x10 ,0x0d ,
			(byte) 0xe2,0x7c ,0x3a , (byte) 0xa6,0x1c , (byte) 0xf5,
			(byte) 0xb7,0x0e ,0x6b ,0x10 , (byte) 0xf7 , (byte) 0x04 , (byte) 0xd9 , (byte) 0xb3 , (byte) 0x9e , (byte) 0xe3 , (byte) 0x30 , (byte) 0xec , (byte) 0xf7 , (byte) 0x7f , (byte) 0x19 , (byte) 0xdc , (byte) 0xa5 , (byte) 0x3b , (byte) 0x07 , (byte) 0xe2 };
	private String argon_password="vM3J@;ya";
	byte[] AES_key=null;

	private final int AES_KEY_LENGTH=32;

	private final int ARGON2_SALT_LENGTH=16;
	private final int iterations = 2;
	private final int memLimit = 1024;
	private final int hashLength = AES_KEY_LENGTH;
	private final int parallelism = 1;

	private static AESGCM aesgcm ;
	private static SecureRandom random;
	private final Poly1305 poly1305;

	private boolean encrypting;

	public XSalsa20Poly1305AuthenticatedCipher() {
		xSalsa20Engine = new XSalsa20Engine();
		poly1305 = new Poly1305();
		aesgcm =  new AESGCM();
		random = new SecureRandom();
	}

	@Override
	public void init(boolean encrypt, SecretKey key, byte[] iv)
			throws GeneralSecurityException {
		encrypting = encrypt;
		KeyParameter k = new KeyParameter(key.getBytes());
		ParametersWithIV params = new ParametersWithIV(k, iv);
		try {


			//derive aes key
			//byte[] iv2 = new SHA3.DigestShake128_256().digest(iv);

			byte[] iv2 = new SHA3.DigestShake128_256().digest(iv);
			AES_key= Arrays.copyOf(iv2,AES_KEY_LENGTH);

			//This can considerably slow down the traffic and even create socket crashes and timeouts
		/*
		byte[] salt= Arrays.copyOf(iv2,ARGON2_SALT_LENGTH);


		Argon2Parameters.Builder builder = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
				.withVersion(Argon2Parameters.ARGON2_VERSION_13)
				.withIterations(iterations)
				.withMemoryAsKB(memLimit)
				.withParallelism(parallelism)
				.withSalt(salt);

		Argon2BytesGenerator generate = new Argon2BytesGenerator();
		generate.init(builder.build());
		byte[] result = new byte[hashLength];
		generate.generateBytes(argon_password.getBytes(), result, 0, result.length);
		AES_key=new byte[AES_KEY_LENGTH];
*/

			for (int i=0;i<AES_KEY_LENGTH;i++) {
				AES_key[i] = (byte) (AES_masterkey[i] ^ AES_key[i]);
			}




			xSalsa20Engine.init(encrypt, params);
		} catch (IllegalArgumentException e) {
			throw new GeneralSecurityException(e.getMessage());
		}
	}

	/*
	////// add-on

				if(encrypting==true)
					{

						javax.crypto.SecretKey Key = new SecretKeySpec(AES_key, 0, AES_key.length, "AES")
						byte[] iv = aesgcm.generateIV(random);
						byte[] toEncrypt =  Arrays.copyOfRange(input,inputOff,inputOff+len-1);
						AESGCM.SealedBox sb = aesgcm.encrypt(Key, iv,toEncrypt,null);

					}

				//////////////////
	 */
	@Override
	public int process(byte[] input, int inputOff, int len, byte[] output,
			int outputOff) throws GeneralSecurityException
	{

		if(encrypting==true)
		{

			javax.crypto.SecretKey Key = new SecretKeySpec(AES_key, 0, AES_key.length, "AES");
			byte[] iv = aesgcm.generateIV(random);
			byte[] toEncrypt =  Arrays.copyOfRange(input,inputOff,inputOff+len);
			//org.bouncycastle.crypto.Digest shake = org.bouncycastle.crypto.util.DigestFactory.createSHAKE128();
			//shake.update(AUTH_TAG_STRING.getBytes(),0,AUTH_TAG_STRING.getBytes().length);
			byte[] authData=new byte[AESGCM.AUTH_TAG_BIT_LENGTH/8];
			//shake.doFinal(authData,0);
			System.arraycopy(new SHA3.DigestShake128_256().digest(AUTH_TAG_STRING.getBytes(
					StandardCharsets.UTF_8)),0,authData,0,AESGCM.AUTH_TAG_BIT_LENGTH/8);

			SealedBox sb = aesgcm.encrypt(Key, iv,toEncrypt,authData);

			byte[] newinput = new byte[sb.getIV().length+sb.getAuthtag().length+sb.getCiphered().length];
			System.arraycopy(sb.getIV(),0,newinput,0,sb.getIV().length);
			System.arraycopy(sb.getAuthtag(),0,newinput,sb.getIV().length,sb.getAuthtag().length);
			System.arraycopy(sb.getCiphered(),0,newinput,sb.getIV().length+sb.getAuthtag().length,sb.getCiphered().length);

			return process_(newinput,0,newinput.length,output,outputOff);

		}
		else
		//decryption
		{

			byte[] output_= new byte[len];
			int len_ = process_(input,inputOff,len,output_,0);

			javax.crypto.SecretKey Key = new SecretKeySpec(AES_key, 0, AES_key.length, "AES");
			byte[] toDecrypt =  Arrays.copyOfRange(output_,0,len_);
			byte[] authData=new byte[AESGCM.AUTH_TAG_BIT_LENGTH/8];
			//shake.doFinal(authData,0);
			System.arraycopy(new SHA3.DigestShake128_256().digest(AUTH_TAG_STRING.getBytes(
					StandardCharsets.UTF_8)),0,authData,0,AESGCM.AUTH_TAG_BIT_LENGTH/8);

			SealedBox sb = new SealedBox();
			sb.fromByteArray(toDecrypt);
			byte[] decrypted=aesgcm.decrypt(Key,sb.getIV(),sb.getCiphered(),authData,sb.getAuthtag());

			System.arraycopy(decrypted,0,output,outputOff,decrypted.length);
			return decrypted.length;
		}

	}


	public int process_(byte[] input, int inputOff, int len, byte[] output,
			int outputOff) throws GeneralSecurityException {
		if (!encrypting && len < MAC_LENGTH)
			throw new GeneralSecurityException("Invalid MAC");
		try {


			// Generate the Poly1305 subkey from an empty array
			byte[] zero = new byte[SUBKEY_LENGTH];
			byte[] subKey = new byte[SUBKEY_LENGTH];
			xSalsa20Engine.processBytes(zero, 0, SUBKEY_LENGTH, subKey, 0);

			//this must be moved in the new process function ?
			// Clamp the subkey
			Poly1305KeyGenerator.clamp(subKey);

			// Initialize Poly1305 with the subkey
			KeyParameter k = new KeyParameter(subKey);
			poly1305.init(k);

			// If we are decrypting, verify the MAC
			if (!encrypting) {
				byte[] mac = new byte[MAC_LENGTH];
				poly1305.update(input, inputOff + MAC_LENGTH, len - MAC_LENGTH);
				poly1305.doFinal(mac, 0);
				// Constant-time comparison
				int cmp = 0;
				for (int i = 0; i < MAC_LENGTH; i++)
					cmp |= mac[i] ^ input[inputOff + i];
				if (cmp != 0)
					throw new GeneralSecurityException("Invalid MAC");
			}

			// Apply or invert the stream encryption
			int processed = xSalsa20Engine.processBytes(
					input, encrypting ? inputOff : inputOff + MAC_LENGTH,
					encrypting ? len : len - MAC_LENGTH,
					output, encrypting ? outputOff + MAC_LENGTH : outputOff);

			// If we are encrypting, generate the MAC
			if (encrypting) {
				poly1305.update(output, outputOff + MAC_LENGTH, len);
				poly1305.doFinal(output, outputOff);
			}

			return encrypting ? processed + MAC_LENGTH : processed;
		} catch (DataLengthException e) {
			throw new GeneralSecurityException(e.getMessage());
		}
	}

	@Override
	public int getMacBytes() {
		return MAC_LENGTH;
	}
}