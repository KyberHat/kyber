package org.briarproject.bramble.sync;

import org.briarproject.bramble.api.crypto.CryptoComponent;
import org.briarproject.bramble.api.nullsafety.NotNullByDefault;
import org.briarproject.bramble.api.sync.MessageFactory;
import org.briarproject.bramble.api.sync.RecordReader;
import org.briarproject.bramble.api.sync.RecordReaderFactory;

import java.io.InputStream;

import javax.annotation.concurrent.Immutable;
import javax.inject.Inject;

@Immutable
@NotNullByDefault
class RecordReaderFactoryImpl implements RecordReaderFactory {

	private final CryptoComponent crypto;
	private final MessageFactory messageFactory;

	@Inject
	RecordReaderFactoryImpl(CryptoComponent crypto,
			MessageFactory messageFactory) {
		this.crypto = crypto;
		this.messageFactory = messageFactory;
	}

	@Override
	public RecordReader createRecordReader(InputStream in) {
		return new RecordReaderImpl(messageFactory, in);
	}
}
