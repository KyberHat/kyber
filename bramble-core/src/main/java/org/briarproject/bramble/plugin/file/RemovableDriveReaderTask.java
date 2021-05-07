package org.briarproject.bramble.plugin.file;

import org.briarproject.bramble.api.connection.ConnectionManager;
import org.briarproject.bramble.api.contact.ContactId;
import org.briarproject.bramble.api.event.Event;
import org.briarproject.bramble.api.event.EventBus;
import org.briarproject.bramble.api.event.EventListener;
import org.briarproject.bramble.api.nullsafety.NotNullByDefault;
import org.briarproject.bramble.api.plugin.PluginManager;
import org.briarproject.bramble.api.plugin.TransportConnectionReader;
import org.briarproject.bramble.api.sync.event.MessageAddedEvent;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.Executor;
import java.util.logging.Logger;

import static java.util.logging.Logger.getLogger;
import static org.briarproject.bramble.api.plugin.file.RemovableDriveConstants.ID;

@NotNullByDefault
class RemovableDriveReaderTask extends RemovableDriveTaskImpl
		implements EventListener {

	private final static Logger LOG =
			getLogger(RemovableDriveReaderTask.class.getName());

	RemovableDriveReaderTask(
			Executor eventExecutor,
			PluginManager pluginManager,
			ConnectionManager connectionManager,
			EventBus eventBus,
			RemovableDriveTaskRegistry registry,
			ContactId contactId,
			File file) {
		super(eventExecutor, pluginManager, connectionManager, eventBus,
				registry, contactId, file);
	}

	@Override
	public void run() {
		TransportConnectionReader r =
				getPlugin().createReader(createProperties());
		if (r == null) {
			LOG.warning("Failed to create reader");
			registry.removeReader(contactId, this);
			setSuccess(false);
			return;
		}
		setTotal(file.length());
		eventBus.addListener(this);
		connectionManager.manageIncomingConnection(ID, new DecoratedReader(r));
	}

	@Override
	public void eventOccurred(Event e) {
		if (e instanceof MessageAddedEvent) {
			MessageAddedEvent m = (MessageAddedEvent) e;
			if (contactId.equals(m.getContactId())) {
				LOG.info("Message received");
				addDone(m.getMessage().getRawLength());
			}
		}
	}

	private class DecoratedReader implements TransportConnectionReader {

		private final TransportConnectionReader delegate;

		private DecoratedReader(TransportConnectionReader delegate) {
			this.delegate = delegate;
		}

		@Override
		public InputStream getInputStream() throws IOException {
			return delegate.getInputStream();
		}

		@Override
		public void dispose(boolean exception, boolean recognised)
				throws IOException {
			delegate.dispose(exception, recognised);
			registry.removeReader(contactId, RemovableDriveReaderTask.this);
			eventBus.removeListener(RemovableDriveReaderTask.this);
			setSuccess(!exception && recognised);
		}
	}
}
