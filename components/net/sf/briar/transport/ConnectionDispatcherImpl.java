package net.sf.briar.transport;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Executor;
import java.util.logging.Level;
import java.util.logging.Logger;

import net.sf.briar.api.ContactId;
import net.sf.briar.api.TransportId;
import net.sf.briar.api.db.DbException;
import net.sf.briar.api.transport.BatchTransportReader;
import net.sf.briar.api.transport.BatchTransportWriter;
import net.sf.briar.api.transport.ConnectionDispatcher;
import net.sf.briar.api.transport.ConnectionRecogniser;
import net.sf.briar.api.transport.ConnectionRecogniserFactory;
import net.sf.briar.api.transport.StreamTransportConnection;
import net.sf.briar.api.transport.TransportConstants;
import net.sf.briar.api.transport.batch.BatchConnectionFactory;
import net.sf.briar.api.transport.stream.StreamConnectionFactory;

public class ConnectionDispatcherImpl implements ConnectionDispatcher {

	private static final Logger LOG =
		Logger.getLogger(ConnectionDispatcherImpl.class.getName());

	private final Executor executor;
	private final ConnectionRecogniserFactory recFactory;
	private final BatchConnectionFactory batchConnFactory;
	private final StreamConnectionFactory streamConnFactory;
	private final Map<TransportId, ConnectionRecogniser> recognisers;

	ConnectionDispatcherImpl(Executor executor,
			ConnectionRecogniserFactory recFactory,
			BatchConnectionFactory batchConnFactory,
			StreamConnectionFactory streamConnFactory) {
		this.executor = executor;
		this.recFactory = recFactory;
		this.batchConnFactory = batchConnFactory;
		this.streamConnFactory = streamConnFactory;
		recognisers = new HashMap<TransportId, ConnectionRecogniser>();
	}

	public void dispatchReader(TransportId t, BatchTransportReader r) {
		// Read the encrypted IV
		byte[] encryptedIv;
		try {
			encryptedIv = readIv(r.getInputStream());
		} catch(IOException e) {
			if(LOG.isLoggable(Level.WARNING)) LOG.warning(e.getMessage());
			r.dispose(false);
			return;
		}
		// Get the contact ID, or null if the IV wasn't expected
		ContactId c;
		try {
			ConnectionRecogniser rec = getRecogniser(t);
			c = rec.acceptConnection(encryptedIv);
		} catch(DbException e) {
			if(LOG.isLoggable(Level.WARNING)) LOG.warning(e.getMessage());
			r.dispose(false);
			return;
		}
		if(c == null) {
			r.dispose(false);
			return;
		}
		// Pass the connection to the executor and return
		executor.execute(batchConnFactory.createIncomingConnection(c, r,
				encryptedIv));
	}

	private byte[] readIv(InputStream in) throws IOException {
		byte[] b = new byte[TransportConstants.IV_LENGTH];
		int offset = 0;
		while(offset < b.length) {
			int read = in.read(b, offset, b.length - offset);
			if(read == -1) throw new IOException();
			offset += read;
		}
		return b;
	}

	private ConnectionRecogniser getRecogniser(TransportId t) {
		synchronized(recognisers) {
			ConnectionRecogniser rec = recognisers.get(t);
			if(rec == null) {
				rec = recFactory.createConnectionRecogniser(t);
				recognisers.put(t, rec);
			}
			return rec;
		}
	}

	public void dispatchWriter(TransportId t, ContactId c,
			BatchTransportWriter w) {
		executor.execute(batchConnFactory.createOutgoingConnection(t, c, w));
	}

	public void dispatchIncomingConnection(TransportId t,
			StreamTransportConnection s) {
		// Read the encrypted IV
		byte[] encryptedIv;
		try {
			encryptedIv = readIv(s.getInputStream());
		} catch(IOException e) {
			if(LOG.isLoggable(Level.WARNING)) LOG.warning(e.getMessage());
			s.dispose(false);
			return;
		}
		// Get the contact ID, or null if the IV wasn't expected
		ContactId c;
		try {
			ConnectionRecogniser rec = getRecogniser(t);
			c = rec.acceptConnection(encryptedIv);
		} catch(DbException e) {
			if(LOG.isLoggable(Level.WARNING)) LOG.warning(e.getMessage());
			s.dispose(false);
			return;
		}
		if(c == null) {
			s.dispose(false);
			return;
		}
		// Pass the connection to the executor and return
		Runnable[] r = streamConnFactory.createIncomingConnection(c, s,
				encryptedIv);
		assert r.length == 2;
		executor.execute(r[0]); // Write
		executor.execute(r[1]); // Read
	}

	public void dispatchOutgoingConnection(TransportId t, ContactId c,
			StreamTransportConnection s) {
		Runnable[] r = streamConnFactory.createOutgoingConnection(t, c, s);
		assert r.length == 2;
		executor.execute(r[0]); // Write
		executor.execute(r[1]); // Read
	}
}
