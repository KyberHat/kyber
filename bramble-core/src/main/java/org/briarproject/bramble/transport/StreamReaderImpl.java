package org.briarproject.bramble.transport;

import org.briarproject.bramble.api.crypto.StreamDecrypter;
import org.briarproject.bramble.crypto.AESGCM;
import org.briarproject.nullsafety.NotNullByDefault;

import java.io.IOException;
import java.io.InputStream;

import javax.annotation.concurrent.NotThreadSafe;

import static org.briarproject.bramble.api.transport.TransportConstants.MAX_PAYLOAD_LENGTH;
import static org.briarproject.bramble.api.transport.TransportConstants.FRAME_HEADER_PLAINTEXT_LENGTH;
import static org.briarproject.bramble.api.transport.TransportConstants.MAC_LENGTH;
import static org.briarproject.bramble.api.transport.TransportConstants.MAX_FRAME_LENGTH;
import static org.briarproject.bramble.api.transport.TransportConstants.STREAM_HEADER_NONCE_LENGTH;
import static org.briarproject.bramble.api.transport.TransportConstants.STREAM_HEADER_PLAINTEXT_LENGTH;

//import static org.briarproject.bramble.api.transport.TransportConstants.MAX_PAYLOAD_LENGTH;

/**
 * An {@link InputStream} that unpacks payload data from transport frames.
 */
@NotThreadSafe
@NotNullByDefault
class StreamReaderImpl extends InputStream {


	/**
	 * The length of the stream header in bytes.
	 */
	private static int STREAM_HEADER_LENGTH = STREAM_HEADER_NONCE_LENGTH
			+  MAX_FRAME_LENGTH -(new AESGCM().computeOutputLength(MAX_FRAME_LENGTH)-MAX_FRAME_LENGTH) + MAC_LENGTH;

	/**
	 * The length of the encrypted and authenticated frame header in bytes.
	 */
	private static int FRAME_HEADER_LENGTH =  new AESGCM().computeOutputLength(FRAME_HEADER_PLAINTEXT_LENGTH) + MAC_LENGTH;

	/**
	 * The maximum total length of the frame payload and padding in bytes.
	 */
	private static int MAX_PAYLOAD_LENGTH = MAX_FRAME_LENGTH -(new AESGCM().computeOutputLength(MAX_FRAME_LENGTH)-MAX_FRAME_LENGTH)- FRAME_HEADER_LENGTH
			- MAC_LENGTH;

	private final StreamDecrypter decrypter;
	private final byte[] payload;

	private int offset = 0, length = 0;

	StreamReaderImpl(StreamDecrypter decrypter) {
		this.decrypter = decrypter;
		payload = new byte[MAX_PAYLOAD_LENGTH];
	}

	@Override
	public int read() throws IOException {
		while (length <= 0) {
			if (length == -1) return -1;
			readFrame();
		}
		int b = payload[offset] & 0xff;
		offset++;
		length--;
		return b;
	}

	@Override
	public int read(byte[] b) throws IOException {
		return read(b, 0, b.length);
	}

	@Override
	public int read(byte[] b, int off, int len) throws IOException {
		while (length <= 0) {
			if (length == -1) return -1;
			readFrame();
		}
		len = Math.min(len, length);
		System.arraycopy(payload, offset, b, off, len);
		offset += len;
		length -= len;
		return len;
	}

	private void readFrame() throws IOException {
		if (length != 0) throw new IllegalStateException();
		offset = 0;
		length = decrypter.readFrame(payload);
	}
}
