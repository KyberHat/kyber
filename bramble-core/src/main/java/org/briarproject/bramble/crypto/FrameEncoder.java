package org.briarproject.bramble.crypto;

import org.briarproject.bramble.util.ByteUtils;
import org.briarproject.nullsafety.NotNullByDefault;

import static org.briarproject.bramble.api.transport.TransportConstants.FRAME_HEADER_PLAINTEXT_LENGTH;
import static org.briarproject.bramble.api.transport.TransportConstants.FRAME_NONCE_LENGTH;
//import static org.briarproject.bramble.api.transport.TransportConstants.MAX_PAYLOAD_LENGTH;
import static org.briarproject.bramble.api.transport.TransportConstants.MAC_LENGTH;
import static org.briarproject.bramble.api.transport.TransportConstants.MAX_FRAME_LENGTH;
import static org.briarproject.bramble.api.transport.TransportConstants.STREAM_HEADER_NONCE_LENGTH;
import static org.briarproject.bramble.api.transport.TransportConstants.STREAM_HEADER_PLAINTEXT_LENGTH;
import static org.briarproject.bramble.util.ByteUtils.INT_16_BYTES;
import static org.briarproject.bramble.util.ByteUtils.INT_64_BYTES;



@NotNullByDefault
public
class FrameEncoder {

	/**
	 * The length of the stream header in bytes.
	 */
	private static int STREAM_HEADER_LENGTH = STREAM_HEADER_NONCE_LENGTH
			+  new AESGCM().computeOutputLength(STREAM_HEADER_PLAINTEXT_LENGTH) + MAC_LENGTH;

	/**
	 * The length of the encrypted and authenticated frame header in bytes.
	 */
	private static int FRAME_HEADER_LENGTH =  new AESGCM().computeOutputLength(FRAME_HEADER_PLAINTEXT_LENGTH) + MAC_LENGTH;

	/**
	 * The maximum total length of the frame payload and padding in bytes.
	 */
	private static int MAX_PAYLOAD_LENGTH =MAX_FRAME_LENGTH -(new AESGCM().computeOutputLength(MAX_FRAME_LENGTH)-MAX_FRAME_LENGTH) - FRAME_HEADER_LENGTH
			- MAC_LENGTH;



	public static void encodeNonce(byte[] dest, long frameNumber,
			boolean header) {
		if (dest.length < FRAME_NONCE_LENGTH)
			throw new IllegalArgumentException();
		if (frameNumber < 0) throw new IllegalArgumentException();
		ByteUtils.writeUint64(frameNumber, dest, 0);
		if (header) dest[0] |= 0x80;
		for (int i = INT_64_BYTES; i < FRAME_NONCE_LENGTH; i++) dest[i] = 0;
	}

	public static void encodeHeader(byte[] dest, boolean finalFrame,
			int payloadLength, int paddingLength) {
		if (dest.length < FRAME_HEADER_PLAINTEXT_LENGTH)
			throw new IllegalArgumentException();
		if (payloadLength < 0) throw new IllegalArgumentException();
		if (paddingLength < 0) throw new IllegalArgumentException();
		if (payloadLength + paddingLength > MAX_PAYLOAD_LENGTH)
			throw new IllegalArgumentException();
		ByteUtils.writeUint16(payloadLength, dest, 0);
		ByteUtils.writeUint16(paddingLength, dest, INT_16_BYTES);
		if (finalFrame) dest[0] |= 0x80;
	}

	public static boolean isFinalFrame(byte[] header) {
		if (header.length < FRAME_HEADER_PLAINTEXT_LENGTH)
			throw new IllegalArgumentException();
		return (header[0] & 0x80) == 0x80;
	}

	public static int getPayloadLength(byte[] header) {
		if (header.length < FRAME_HEADER_PLAINTEXT_LENGTH)
			throw new IllegalArgumentException();
		return ByteUtils.readUint16(header, 0) & 0x7FFF;
	}

	public static int getPaddingLength(byte[] header) {
		if (header.length < FRAME_HEADER_PLAINTEXT_LENGTH)
			throw new IllegalArgumentException();
		return ByteUtils.readUint16(header, INT_16_BYTES);
	}
}