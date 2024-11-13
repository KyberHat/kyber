package org.briarproject.bramble.sync;

import org.briarproject.bramble.api.contact.ContactId;
import org.briarproject.bramble.api.db.DatabaseComponent;
import org.briarproject.bramble.api.db.DatabaseExecutor;
import org.briarproject.bramble.api.event.EventBus;
import org.briarproject.bramble.api.plugin.TransportId;
import org.briarproject.bramble.api.sync.OutgoingSessionRecord;
import org.briarproject.bramble.api.sync.Priority;
import org.briarproject.bramble.api.sync.PriorityHandler;
import org.briarproject.bramble.api.sync.SyncRecordReader;
import org.briarproject.bramble.api.sync.SyncRecordReaderFactory;
import org.briarproject.bramble.api.sync.SyncRecordWriter;
import org.briarproject.bramble.api.sync.SyncRecordWriterFactory;
import org.briarproject.bramble.api.sync.SyncSession;
import org.briarproject.bramble.api.sync.SyncSessionFactory;
import org.briarproject.bramble.api.system.Clock;
import org.briarproject.bramble.api.transport.StreamWriter;
import org.briarproject.nullsafety.NotNullByDefault;
import org.briarproject.bramble.crypto.AESGCM;

import static org.briarproject.bramble.api.mailbox.MailboxConstants.MAX_FILE_BYTES;
//import static org.briarproject.bramble.api.mailbox.MailboxConstants.MAX_FILE_PAYLOAD_BYTES;
import static org.briarproject.bramble.api.transport.TransportConstants.FRAME_HEADER_PLAINTEXT_LENGTH;
import static org.briarproject.bramble.api.transport.TransportConstants.MAC_LENGTH;
import static org.briarproject.bramble.api.transport.TransportConstants.MAX_FRAME_LENGTH;
import static org.briarproject.bramble.api.transport.TransportConstants.STREAM_HEADER_NONCE_LENGTH;
import static org.briarproject.bramble.api.transport.TransportConstants.STREAM_HEADER_PLAINTEXT_LENGTH;
import static org.briarproject.bramble.api.transport.TransportConstants.TAG_LENGTH;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.concurrent.Executor;

import javax.annotation.Nullable;
import javax.annotation.concurrent.Immutable;
import javax.inject.Inject;

import static org.briarproject.bramble.api.mailbox.MailboxConstants.MAX_FILE_PAYLOAD_BYTES;

@Immutable
@NotNullByDefault
class SyncSessionFactoryImpl implements SyncSessionFactory {

	private final DatabaseComponent db;
	private final Executor dbExecutor;
	private final EventBus eventBus;
	private final Clock clock;
	private final SyncRecordReaderFactory recordReaderFactory;
	private final SyncRecordWriterFactory recordWriterFactory;


	/**
	 * The length of the stream header in bytes.
	 */
	private int STREAM_HEADER_LENGTH = STREAM_HEADER_NONCE_LENGTH
			+  new AESGCM().computeOutputLength(STREAM_HEADER_PLAINTEXT_LENGTH) + MAC_LENGTH;

	/**
	 * The length of the encrypted and authenticated frame header in bytes.
	 */
	int FRAME_HEADER_LENGTH =  new AESGCM().computeOutputLength(FRAME_HEADER_PLAINTEXT_LENGTH) + MAC_LENGTH;

	/**
	 * The maximum total length of the frame payload and padding in bytes.
	 */
	private int MAX_PAYLOAD_LENGTH =  MAX_FRAME_LENGTH -(new AESGCM().computeOutputLength(MAX_FRAME_LENGTH)-MAX_FRAME_LENGTH) - FRAME_HEADER_LENGTH
			- MAC_LENGTH;



	/**
	 * The maximum length of the plaintext payload of a file, such that the
	 * ciphertext is no more than MAX_FILE_BYTES.
	 */
	int MAX_FILE_PAYLOAD_BYTES =
			(MAX_FILE_BYTES - TAG_LENGTH - STREAM_HEADER_LENGTH)
					/  MAX_FRAME_LENGTH * MAX_PAYLOAD_LENGTH;
	@Inject
	SyncSessionFactoryImpl(DatabaseComponent db,
			@DatabaseExecutor Executor dbExecutor, EventBus eventBus,
			Clock clock, SyncRecordReaderFactory recordReaderFactory,
			SyncRecordWriterFactory recordWriterFactory) {
		this.db = db;
		this.dbExecutor = dbExecutor;
		this.eventBus = eventBus;
		this.clock = clock;
		this.recordReaderFactory = recordReaderFactory;
		this.recordWriterFactory = recordWriterFactory;
	}

	@Override
	public SyncSession createIncomingSession(ContactId c, InputStream in,
			PriorityHandler handler) {
		SyncRecordReader recordReader =
				recordReaderFactory.createRecordReader(in);
		return new IncomingSession(db, dbExecutor, eventBus, c, recordReader,
				handler);
	}

	@Override
	public SyncSession createSimplexOutgoingSession(ContactId c, TransportId t,
			long maxLatency, boolean eager, StreamWriter streamWriter) {
		OutputStream out = streamWriter.getOutputStream();
		SyncRecordWriter recordWriter =
				recordWriterFactory.createRecordWriter(out);
		if (eager) {
			return new EagerSimplexOutgoingSession(db, eventBus, c, t,
					maxLatency, streamWriter, recordWriter);
		} else {
			return new SimplexOutgoingSession(db, eventBus, c, t,
					maxLatency, streamWriter, recordWriter);
		}
	}

	@Override
	public SyncSession createSimplexOutgoingSession(ContactId c, TransportId t,
			long maxLatency, StreamWriter streamWriter,
			OutgoingSessionRecord sessionRecord) {
		OutputStream out = streamWriter.getOutputStream();
		SyncRecordWriter recordWriter =
				recordWriterFactory.createRecordWriter(out);
		return new MailboxOutgoingSession(db, eventBus, c, t, maxLatency,
				streamWriter, recordWriter, sessionRecord,
				MAX_FILE_PAYLOAD_BYTES);
	}

	@Override
	public SyncSession createDuplexOutgoingSession(ContactId c, TransportId t,
			long maxLatency, int maxIdleTime, StreamWriter streamWriter,
			@Nullable Priority priority) {
		OutputStream out = streamWriter.getOutputStream();
		SyncRecordWriter recordWriter =
				recordWriterFactory.createRecordWriter(out);
		return new DuplexOutgoingSession(db, dbExecutor, eventBus, clock, c, t,
				maxLatency, maxIdleTime, streamWriter, recordWriter, priority);
	}
}
