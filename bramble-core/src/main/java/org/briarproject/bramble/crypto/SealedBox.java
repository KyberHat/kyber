package org.briarproject.bramble.crypto;

import static org.briarproject.bramble.crypto.AESGCM.AUTH_TAG_BIT_LENGTH;
import static org.briarproject.bramble.crypto.AESGCM.IV_BIT_LENGTH;

public class SealedBox
{

	private byte[] ciphered;
	private byte[] authtag;

	private byte[] IV;


	public void fromByteArray(byte[] data)
	{
		IV = new byte[IV_BIT_LENGTH/8];
		authtag= new byte[AUTH_TAG_BIT_LENGTH/8];
		ciphered= new byte[data.length-(IV_BIT_LENGTH/8+AUTH_TAG_BIT_LENGTH/8)];
		//IV+TAG+ENCRYPTED
		System.arraycopy(data,0,IV,0,IV_BIT_LENGTH/8);
		System.arraycopy(data,IV_BIT_LENGTH/8,authtag,0,AUTH_TAG_BIT_LENGTH/8);
		System.arraycopy(data,IV_BIT_LENGTH/8+AUTH_TAG_BIT_LENGTH/8,ciphered,0,data.length-(IV_BIT_LENGTH/8+AUTH_TAG_BIT_LENGTH/8));

	}
	public SealedBox()
	{


	}
	public SealedBox(byte[] ciphered_,byte[] authtag_,byte[] IV_)
	{
		ciphered=ciphered_;
		authtag=authtag_;
		IV=IV_;
	}

	public byte[] getCiphered() {
		return ciphered;
	}

	public byte[] getAuthtag() {
		return authtag;
	}

	public byte[] getIV() {
		return IV;
	}
}