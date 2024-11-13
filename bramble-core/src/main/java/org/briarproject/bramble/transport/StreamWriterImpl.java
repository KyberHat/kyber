package org.briarproject.bramble.transport;

import org.briarproject.bramble.api.crypto.StreamEncrypter;
import org.briarproject.bramble.api.transport.StreamWriter;
import org.briarproject.nullsafety.NotNullByDefault;
import org.briarproject.bramble.crypto.AESGCM;

import java.io.IOException;
import java.io.OutputStream;

import javax.annotation.concurrent.NotThreadSafe;


import static org.briarproject.bramble.api.transport.TransportConstants.FRAME_HEADER_PLAINTEXT_LENGTH;
import static org.briarproject.bramble.api.transport.TransportConstants.MAC_LENGTH;
import static org.briarproject.bramble.api.transport.TransportConstants.MAX_FRAME_LENGTH;
import static org.briarproject.bramble.api.transport.TransportConstants.STREAM_HEADER_NONCE_LENGTH;
import static org.briarproject.bramble.api.transport.TransportConstants.STREAM_HEADER_PLAINTEXT_LENGTH;

//import static org.briarproject.bramble.api.transport.TransportConstants.MAX_PAYLOAD_LENGTH;
import static org.briarproject.bramble.api.transport.TransportConstants.MAX_PAYLOAD_LENGTH;

/**
 * An {@link OutputStream} that packs data into transport frames, writing a
 * frame whenever there is a full frame to write or the {@link #flush()} method
 * is called.
 */
@NotThreadSafe
@NotNullByDefault
class StreamWriterImpl extends OutputStream implements StreamWriter {


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
	private static int MAX_PAYLOAD_LENGTH =  MAX_FRAME_LENGTH -(new AESGCM().computeOutputLength(MAX_FRAME_LENGTH)-MAX_FRAME_LENGTH) - FRAME_HEADER_LENGTH
			- MAC_LENGTH;
	private final StreamEncrypter encrypter;
	private final byte[] payload;

	private int length = 0;

	StreamWriterImpl(StreamEncrypter encrypter) {
		this.encrypter = encrypter;
		payload = new byte[MAX_PAYLOAD_LENGTH];
	}

	@Override
	public OutputStream getOutputStream() {
		return this;
	}

	@Override
	public void sendEndOfStream() throws IOException {
		writeFrame(true);
		encrypter.flush();
	}

	@Override
	public void close() throws IOException {
		writeFrame(true);
		encrypter.flush();
		super.close();
	}

	@Override
	public void flush() throws IOException {
		writeFrame(false);
		encrypter.flush();
	}

	@Override
	public void write(int b) throws IOException {
		payload[length] = (byte) b;
		length++;
		if (length == payload.length) writeFrame(false);
	}

	@Override
	public void write(byte[] b) throws IOException {
		write(b, 0, b.length);
	}

	@Override
	public void write(byte[] b, int off, int len) throws IOException {
		int available = payload.length - length;
		while (available <= len) {
			System.arraycopy(b, off, payload, length, available);
			length += available;
			writeFrame(false);
			off += available;
			len -= available;
			available = payload.length - length;
		}
		System.arraycopy(b, off, payload, length, len);
		length += len;
	}

	private void writeFrame(boolean finalFrame) throws IOException {
		encrypter.writeFrame(payload, length, 0, finalFrame);
		length = 0;
	}
}
