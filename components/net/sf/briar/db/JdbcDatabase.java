package net.sf.briar.db;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.sql.Blob;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import net.sf.briar.api.db.DatabaseComponent;
import net.sf.briar.api.db.DbException;
import net.sf.briar.api.db.ContactId;
import net.sf.briar.api.db.Rating;
import net.sf.briar.api.db.Status;
import net.sf.briar.api.protocol.AuthorId;
import net.sf.briar.api.protocol.BatchId;
import net.sf.briar.api.protocol.BundleId;
import net.sf.briar.api.protocol.GroupId;
import net.sf.briar.api.protocol.Message;
import net.sf.briar.api.protocol.MessageFactory;
import net.sf.briar.api.protocol.MessageId;
import net.sf.briar.util.FileUtils;

/**
 * A generic database implementation that can be used with any JDBC-compatible
 * database library. (Tested with H2, Derby and HSQLDB.)
 */
abstract class JdbcDatabase implements Database<Connection> {

	private static final String CREATE_LOCAL_SUBSCRIPTIONS =
		"CREATE TABLE localSubscriptions"
		+ " (groupId XXXX NOT NULL,"
		+ " PRIMARY KEY (groupId))";

	private static final String CREATE_MESSAGES =
		"CREATE TABLE messages"
		+ " (messageId XXXX NOT NULL,"
		+ " parentId XXXX NOT NULL,"
		+ " groupId XXXX NOT NULL,"
		+ " authorId XXXX NOT NULL,"
		+ " timestamp BIGINT NOT NULL,"
		+ " size INT NOT NULL,"
		+ " body BLOB NOT NULL,"
		+ " sendability INT NOT NULL,"
		+ " PRIMARY KEY (messageId),"
		+ " FOREIGN KEY (groupId) REFERENCES localSubscriptions (groupId)"
		+ " ON DELETE CASCADE)";

	private static final String INDEX_MESSAGES_BY_PARENT =
		"CREATE INDEX messagesByParent ON messages (parentId)";

	private static final String INDEX_MESSAGES_BY_AUTHOR =
		"CREATE INDEX messagesByAuthor ON messages (authorId)";

	private static final String INDEX_MESSAGES_BY_TIMESTAMP =
		"CREATE INDEX messagesByTimestamp ON messages (timestamp)";

	private static final String INDEX_MESSAGES_BY_SENDABILITY =
		"CREATE INDEX messagesBySendability ON messages (sendability)";

	private static final String CREATE_CONTACTS =
		"CREATE TABLE contacts"
		+ " (contactId INT NOT NULL,"
		+ " lastBundleReceived XXXX NOT NULL,"
		+ " PRIMARY KEY (contactId))";

	private static final String CREATE_BATCHES_TO_ACK =
		"CREATE TABLE batchesToAck"
		+ " (batchId XXXX NOT NULL,"
		+ " contactId INT NOT NULL,"
		+ " PRIMARY KEY (batchId),"
		+ " FOREIGN KEY (contactId) REFERENCES contacts (contactId)"
		+ " ON DELETE CASCADE)";

	private static final String CREATE_CONTACT_SUBSCRIPTIONS =
		"CREATE TABLE contactSubscriptions"
		+ " (contactId INT NOT NULL,"
		+ " groupId XXXX NOT NULL,"
		+ " PRIMARY KEY (contactId, groupId),"
		+ " FOREIGN KEY (contactId) REFERENCES contacts (contactId)"
		+ " ON DELETE CASCADE)";

	private static final String CREATE_OUTSTANDING_BATCHES =
		"CREATE TABLE outstandingBatches"
		+ " (batchId XXXX NOT NULL,"
		+ " contactId INT NOT NULL,"
		+ " lastBundleReceived XXXX NOT NULL,"
		+ " PRIMARY KEY (batchId),"
		+ " FOREIGN KEY (contactId) REFERENCES contacts (contactId)"
		+ " ON DELETE CASCADE)";

	private static final String CREATE_OUTSTANDING_MESSAGES =
		"CREATE TABLE outstandingMessages"
		+ " (batchId XXXX NOT NULL,"
		+ " contactId INT NOT NULL,"
		+ " messageId XXXX NOT NULL,"
		+ " PRIMARY KEY (batchId, messageId),"
		+ " FOREIGN KEY (batchId) REFERENCES outstandingBatches (batchId)"
		+ " ON DELETE CASCADE,"
		+ " FOREIGN KEY (contactId) REFERENCES contacts (contactId)"
		+ " ON DELETE CASCADE,"
		+ " FOREIGN KEY (messageId) REFERENCES messages (messageId)"
		+ " ON DELETE CASCADE)";

	private static final String INDEX_OUTSTANDING_MESSAGES_BY_BATCH =
		"CREATE INDEX outstandingMessagesByBatch"
		+ " ON outstandingMessages (batchId)";

	private static final String CREATE_RATINGS =
		"CREATE TABLE ratings"
		+ " (authorId XXXX NOT NULL,"
		+ " rating SMALLINT NOT NULL,"
		+ " PRIMARY KEY (authorId))";

	private static final String CREATE_RECEIVED_BUNDLES =
		"CREATE TABLE receivedBundles"
		+ " (bundleId XXXX NOT NULL,"
		+ " contactId INT NOT NULL,"
		+ " timestamp BIGINT NOT NULL,"
		+ " PRIMARY KEY (bundleId),"
		+ " FOREIGN KEY (contactId) REFERENCES contacts (contactId)"
		+ " ON DELETE CASCADE)";

	private static final String CREATE_STATUSES =
		"CREATE TABLE statuses"
		+ " (messageId XXXX NOT NULL,"
		+ " contactId INT NOT NULL,"
		+ " status SMALLINT NOT NULL,"
		+ " PRIMARY KEY (messageId, contactId),"
		+ " FOREIGN KEY (messageId) REFERENCES messages (messageId)"
		+ " ON DELETE CASCADE,"
		+ " FOREIGN KEY (contactId) REFERENCES contacts (contactId)"
		+ " ON DELETE CASCADE)";

	private static final String INDEX_STATUSES_BY_MESSAGE =
		"CREATE INDEX statusesByMessage ON statuses (messageId)";

	private static final String INDEX_STATUSES_BY_CONTACT =
		"CREATE INDEX statusesByContact ON statuses (contactId)";

	private static final Logger LOG =
		Logger.getLogger(JdbcDatabase.class.getName());

	private final MessageFactory messageFactory;
	private final String hashType;
	private final LinkedList<Connection> connections =
		new LinkedList<Connection>(); // Locking: self

	private volatile int openConnections = 0; // Locking: connections
	private volatile boolean closed = false; // Locking: connections

	protected abstract Connection createConnection() throws SQLException;

	JdbcDatabase(MessageFactory messageFactory, String hashType) {
		this.messageFactory = messageFactory;
		this.hashType = hashType;
	}

	protected void open(boolean resume, File dir, String driverClass)
	throws DbException {
		if(resume) {
			assert dir.exists();
			assert dir.isDirectory();
			if(LOG.isLoggable(Level.FINE))
				LOG.fine("Resuming from " + dir.getPath());
		} else {
			if(dir.exists()) FileUtils.delete(dir);
		}
		try {
			Class.forName(driverClass);
		} catch(ClassNotFoundException e) {
			throw new DbException(e);
		}
		Connection txn = startTransaction();
		try {
			// If not resuming, create the tables
			if(resume) {
				if(LOG.isLoggable(Level.FINE))
					LOG.fine(getNumberOfMessages(txn) + " messages");
			}
			else createTables(txn);
			commitTransaction(txn);
		} catch(DbException e) {
			abortTransaction(txn);
			throw e;
		}
	}

	private void createTables(Connection txn) throws DbException {
		Statement s = null;
		try {
			s = txn.createStatement();
			if(LOG.isLoggable(Level.FINE))
				LOG.fine("Creating localSubscriptions table");
			s.executeUpdate(insertHashType(CREATE_LOCAL_SUBSCRIPTIONS));
			if(LOG.isLoggable(Level.FINE))
				LOG.fine("Creating messages table");
			s.executeUpdate(insertHashType(CREATE_MESSAGES));
			s.executeUpdate(INDEX_MESSAGES_BY_PARENT);
			s.executeUpdate(INDEX_MESSAGES_BY_AUTHOR);
			s.executeUpdate(INDEX_MESSAGES_BY_TIMESTAMP);
			s.executeUpdate(INDEX_MESSAGES_BY_SENDABILITY);
			if(LOG.isLoggable(Level.FINE))
				LOG.fine("Creating contacts table");
			s.executeUpdate(insertHashType(CREATE_CONTACTS));
			if(LOG.isLoggable(Level.FINE))
				LOG.fine("Creating batchesToAck table");
			s.executeUpdate(insertHashType(CREATE_BATCHES_TO_ACK));
			if(LOG.isLoggable(Level.FINE))
				LOG.fine("Creating contactSubscriptions table");
			s.executeUpdate(insertHashType(CREATE_CONTACT_SUBSCRIPTIONS));
			if(LOG.isLoggable(Level.FINE))
				LOG.fine("Creating outstandingBatches table");
			s.executeUpdate(insertHashType(CREATE_OUTSTANDING_BATCHES));
			if(LOG.isLoggable(Level.FINE))
				LOG.fine("Creating outstandingMessages table");
			s.executeUpdate(insertHashType(CREATE_OUTSTANDING_MESSAGES));
			s.executeUpdate(INDEX_OUTSTANDING_MESSAGES_BY_BATCH);
			if(LOG.isLoggable(Level.FINE))
				LOG.fine("Creating ratings table");
			s.executeUpdate(insertHashType(CREATE_RATINGS));
			if(LOG.isLoggable(Level.FINE))
				LOG.fine("Creating receivedBundles table");
			s.executeUpdate(insertHashType(CREATE_RECEIVED_BUNDLES));
			if(LOG.isLoggable(Level.FINE))
				LOG.fine("Creating statuses table");
			s.executeUpdate(insertHashType(CREATE_STATUSES));
			s.executeUpdate(INDEX_STATUSES_BY_MESSAGE);
			s.executeUpdate(INDEX_STATUSES_BY_CONTACT);
			s.close();
		} catch(SQLException e) {
			tryToClose(s);
			tryToClose(txn);
			throw new DbException(e);
		}
	}

	// FIXME: Get rid of this if we're definitely not using Derby
	private String insertHashType(String s) {
		return s.replaceAll("XXXX", hashType);
	}

	private void tryToClose(Connection c) {
		if(c != null) try {
			c.close();
		} catch(SQLException ignored) {}
	}

	private void tryToClose(Statement s) {
		if(s != null) try {
			s.close();
		} catch(SQLException ignored) {}
	}

	private void tryToClose(ResultSet rs) {
		if(rs != null) try {
			rs.close();
		} catch(SQLException ignored) {}
	}

	public Connection startTransaction() throws DbException {
		Connection txn = null;
		try {
			synchronized(connections) {
				// If the database has been closed, don't return
				while(closed) {
					try {
						connections.wait();
					} catch(InterruptedException ignored) {}
				}
				txn = connections.poll();
			}
			if(txn == null) {
				txn = createConnection();
				assert txn != null;
				synchronized(connections) {
					openConnections++;
					if(LOG.isLoggable(Level.FINE))
						LOG.fine(openConnections + " open connections");
				}
			}
			txn.setAutoCommit(false);
			return txn;
		} catch(SQLException e) {
			tryToClose(txn);
			throw new DbException(e);
		}
	}

	public void abortTransaction(Connection txn) {
		try {
			txn.rollback();
			txn.setAutoCommit(true);
			synchronized(connections) {
				connections.add(txn);
				connections.notifyAll();
			}
		} catch(SQLException e) {
			tryToClose(txn);
		}
	}

	public void commitTransaction(Connection txn) throws DbException {
		try {
			txn.commit();
			txn.setAutoCommit(true);
			synchronized(connections) {
				connections.add(txn);
				connections.notifyAll();
			}
		} catch(SQLException e) {
			tryToClose(txn);
			throw new DbException(e);
		}
	}

	protected void closeAllConnections() throws SQLException {
		synchronized(connections) {
			closed = true;
			for(Connection c : connections) c.close();
			openConnections -= connections.size();
			connections.clear();
			while(openConnections > 0) {
				if(LOG.isLoggable(Level.FINE))
					LOG.fine("Waiting for " + openConnections
							+ " open connections");
				try {
					connections.wait();
				} catch(InterruptedException ignored) {}
				for(Connection c : connections) c.close();
				openConnections -= connections.size();
				connections.clear();
			}
		}
	}

	public void addBatchToAck(Connection txn, ContactId c, BatchId b)
	throws DbException {
		PreparedStatement ps = null;
		try {
			String sql = "INSERT INTO batchesToAck"
				+ " (batchId, contactId)"
				+ " VALUES (?, ?)";
			ps = txn.prepareStatement(sql);
			ps.setBytes(1, b.getBytes());
			ps.setInt(2, c.getInt());
			int rowsAffected = ps.executeUpdate();
			assert rowsAffected == 1;
			ps.close();
		} catch(SQLException e) {
			tryToClose(ps);
			tryToClose(txn);
			throw new DbException(e);
		}
	}

	public void addContact(Connection txn, ContactId c) throws DbException {
		PreparedStatement ps = null;
		try {
			String sql = "INSERT INTO contacts"
				+ " (contactId, lastBundleReceived)"
				+ " VALUES (?, ?)";
			ps = txn.prepareStatement(sql);
			ps.setInt(1, c.getInt());
			ps.setBytes(2, BundleId.NONE.getBytes());
			int rowsAffected = ps.executeUpdate();
			assert rowsAffected == 1;
			ps.close();
		} catch(SQLException e) {
			tryToClose(ps);
			tryToClose(txn);
			throw new DbException(e);
		}
	}

	public boolean addMessage(Connection txn, Message m) throws DbException {
		if(containsMessage(txn, m.getId())) return false;
		PreparedStatement ps = null;
		try {
			String sql = "INSERT INTO messages"
				+ " (messageId, parentId, groupId, authorId, timestamp, size,"
				+ " body, sendability)"
				+ " VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
			ps = txn.prepareStatement(sql);
			ps.setBytes(1, m.getId().getBytes());
			ps.setBytes(2, m.getParent().getBytes());
			ps.setBytes(3, m.getGroup().getBytes());
			ps.setBytes(4, m.getAuthor().getBytes());
			ps.setLong(5, m.getTimestamp());
			ps.setInt(6, m.getSize());
			ps.setBlob(7, new ByteArrayInputStream(m.getBody()));
			ps.setInt(8, 0);
			int rowsAffected = ps.executeUpdate();
			assert rowsAffected == 1;
			ps.close();
			return true;
		} catch(SQLException e) {
			tryToClose(ps);
			tryToClose(txn);
			throw new DbException(e);
		}
	}

	public void addOutstandingBatch(Connection txn, ContactId c, BatchId b,
			Set<MessageId> sent) throws DbException {
		PreparedStatement ps = null;
		ResultSet rs = null;
		try {
			// Find the ID of the last bundle received from c
			String sql = "SELECT lastBundleReceived FROM contacts"
				+ " WHERE contactId = ?";
			ps = txn.prepareStatement(sql);
			ps.setInt(1, c.getInt());
			rs = ps.executeQuery();
			boolean found = rs.next();
			assert found;
			byte[] lastBundleReceived = rs.getBytes(1);
			boolean more = rs.next();
			assert !more;
			rs.close();
			ps.close();
			// Create an outstanding batch row
			sql = "INSERT INTO outstandingBatches"
				+ " (batchId, contactId, lastBundleReceived)"
				+ " VALUES (?, ?, ?)";
			ps = txn.prepareStatement(sql);
			ps.setBytes(1, b.getBytes());
			ps.setInt(2, c.getInt());
			ps.setBytes(3, lastBundleReceived);
			int rowsAffected = ps.executeUpdate();
			assert rowsAffected == 1;
			ps.close();
			// Create an outstanding message row for each message in the batch
			sql = "INSERT INTO outstandingMessages"
				+ " (batchId, contactId, messageId)"
				+ " VALUES (?, ?, ?)";
			ps = txn.prepareStatement(sql);
			ps.setBytes(1, b.getBytes());
			ps.setInt(2, c.getInt());
			for(MessageId m : sent) {
				ps.setBytes(3, m.getBytes());
				ps.addBatch();
			}
			int[] rowsAffected1 = ps.executeBatch();
			assert rowsAffected1.length == sent.size();
			for(int i = 0; i < rowsAffected1.length; i++) {
				assert rowsAffected1[i] == 1;
			}
			ps.close();
			// Set the status of each message in the batch to SENT
			sql = "UPDATE statuses SET status = ?"
				+ " WHERE messageId = ? AND contactId = ? AND status = ?";
			ps = txn.prepareStatement(sql);
			ps.setShort(1, (short) Status.SENT.ordinal());
			ps.setInt(3, c.getInt());
			ps.setShort(4, (short) Status.NEW.ordinal());
			for(MessageId m : sent) {
				ps.setBytes(2, m.getBytes());
				ps.addBatch();
			}
			rowsAffected1 = ps.executeBatch();
			assert rowsAffected1.length == sent.size();
			for(int i = 0; i < rowsAffected1.length; i++) {
				assert rowsAffected1[i] <= 1;
			}
			ps.close();
		} catch(SQLException e) {
			tryToClose(rs);
			tryToClose(ps);
			tryToClose(txn);
			throw new DbException(e);
		}
	}

	public Set<BatchId> addReceivedBundle(Connection txn, ContactId c,
			BundleId b) throws DbException {
		PreparedStatement ps = null;
		ResultSet rs = null;
		try {
			// Update the ID of the last bundle received from c
			String sql = "UPDATE contacts SET lastBundleReceived = ?"
				+ " WHERE contactId = ?";
			ps = txn.prepareStatement(sql);
			ps.setBytes(1, b.getBytes());
			ps.setInt(2, c.getInt());
			int rowsAffected = ps.executeUpdate();
			assert rowsAffected == 1;
			ps.close();
			// Count the received bundle records for c and find the oldest
			sql = "SELECT bundleId, timestamp FROM receivedBundles"
				+ " WHERE contactId = ?";
			ps = txn.prepareStatement(sql);
			ps.setInt(1, c.getInt());
			rs = ps.executeQuery();
			int received = 0;
			long oldestTimestamp = Long.MAX_VALUE;
			byte[] oldestBundle = null;
			while(rs.next()) {
				received++;
				byte[] bundle = rs.getBytes(1);
				long timestamp = rs.getLong(2);
				if(timestamp < oldestTimestamp) {
					oldestTimestamp = timestamp;
					oldestBundle = bundle;
				}
			}
			rs.close();
			ps.close();
			Set<BatchId> lost;
			if(received == DatabaseComponent.RETRANSMIT_THRESHOLD) {
				// Expire batches related to the oldest received bundle
				assert oldestBundle != null;
				lost = findLostBatches(txn, c, oldestBundle);
				sql = "DELETE FROM receivedBundles WHERE bundleId = ?";
				ps = txn.prepareStatement(sql);
				ps.setBytes(1, oldestBundle);
				rowsAffected = ps.executeUpdate();
				assert rowsAffected == 1;
				ps.close();
			} else {
				lost = Collections.emptySet();
			}
			// Record the new received bundle
			sql = "INSERT INTO receivedBundles"
				+ " (bundleId, contactId, timestamp)"
				+ " VALUES (?, ?, ?)";
			ps = txn.prepareStatement(sql);
			ps.setBytes(1, b.getBytes());
			ps.setInt(2, c.getInt());
			ps.setLong(3, System.currentTimeMillis());
			rowsAffected = ps.executeUpdate();
			assert rowsAffected == 1;
			ps.close();
			return lost;
		} catch(SQLException e) {
			tryToClose(rs);
			tryToClose(ps);
			tryToClose(txn);
			throw new DbException(e);
		}
	}

	private Set<BatchId> findLostBatches(Connection txn, ContactId c,
			byte[] lastBundleReceived) throws DbException {
		PreparedStatement ps = null;
		ResultSet rs = null;
		try {
			String sql = "SELECT batchId FROM outstandingBatches"
				+ " WHERE contactId = ? AND lastBundleReceived = ?";
			ps = txn.prepareStatement(sql);
			ps.setInt(1, c.getInt());
			ps.setBytes(2, lastBundleReceived);
			rs = ps.executeQuery();
			Set<BatchId> lost = new HashSet<BatchId>();
			while(rs.next()) lost.add(new BatchId(rs.getBytes(1)));
			rs.close();
			ps.close();
			return lost;
		} catch(SQLException e) {
			tryToClose(rs);
			tryToClose(ps);
			tryToClose(txn);
			throw new DbException(e);
		}
	}

	public void addSubscription(Connection txn, GroupId g) throws DbException {
		PreparedStatement ps = null;
		try {
			String sql = "INSERT INTO localSubscriptions (groupId) VALUES (?)";
			ps = txn.prepareStatement(sql);
			ps.setBytes(1, g.getBytes());
			int rowsAffected = ps.executeUpdate();
			assert rowsAffected == 1;
			ps.close();
		} catch(SQLException e) {
			tryToClose(ps);
			tryToClose(txn);
			throw new DbException(e);
		}
	}

	public void addSubscription(Connection txn, ContactId c, GroupId g)
	throws DbException {
		PreparedStatement ps = null;
		try {
			String sql = "INSERT INTO contactSubscriptions"
				+ " (contactId, groupId)"
				+ " VALUES (?, ?)";
			ps = txn.prepareStatement(sql);
			ps.setInt(1, c.getInt());
			ps.setBytes(2, g.getBytes());
			int rowsAffected = ps.executeUpdate();
			assert rowsAffected == 1;
			ps.close();
		} catch(SQLException e) {
			tryToClose(ps);
			tryToClose(txn);
			throw new DbException(e);
		}
	}

	public void clearSubscriptions(Connection txn, ContactId c)
	throws DbException {
		PreparedStatement ps = null;
		try {
			String sql = "DELETE FROM contactSubscriptions"
				+ " WHERE contactId = ?";
			ps = txn.prepareStatement(sql);
			ps.setInt(1, c.getInt());
			ps.executeUpdate();
			ps.close();
		} catch(SQLException e) {
			tryToClose(ps);
			tryToClose(txn);
			throw new DbException(e);
		}
	}

	public boolean containsContact(Connection txn, ContactId c)
	throws DbException {
		PreparedStatement ps = null;
		ResultSet rs = null;
		try {
			String sql = "SELECT COUNT(contactId) FROM contacts"
				+ " WHERE contactId = ?";
			ps = txn.prepareStatement(sql);
			ps.setInt(1, c.getInt());
			rs = ps.executeQuery();
			boolean found = rs.next();
			assert found;
			int count = rs.getInt(1);
			assert count <= 1;
			boolean more = rs.next();
			assert !more;
			rs.close();
			ps.close();
			return count > 0;
		} catch(SQLException e) {
			tryToClose(rs);
			tryToClose(ps);
			tryToClose(txn);
			throw new DbException(e);
		}
	}

	public boolean containsMessage(Connection txn, MessageId m)
	throws DbException {
		PreparedStatement ps = null;
		ResultSet rs = null;
		try {
			String sql = "SELECT COUNT(messageId) FROM messages"
				+ " WHERE messageId = ?";
			ps = txn.prepareStatement(sql);
			ps.setBytes(1, m.getBytes());
			rs = ps.executeQuery();
			boolean found = rs.next();
			assert found;
			int count = rs.getInt(1);
			assert count <= 1;
			boolean more = rs.next();
			assert !more;
			rs.close();
			ps.close();
			return count > 0;
		} catch(SQLException e) {
			tryToClose(rs);
			tryToClose(ps);
			tryToClose(txn);
			throw new DbException(e);
		}
	}

	public boolean containsSubscription(Connection txn, GroupId g)
	throws DbException {
		PreparedStatement ps = null;
		ResultSet rs = null;
		try {
			String sql = "SELECT COUNT(groupId) FROM localSubscriptions"
				+ " WHERE groupId = ?";
			ps = txn.prepareStatement(sql);
			ps.setBytes(1, g.getBytes());
			rs = ps.executeQuery();
			boolean found = rs.next();
			assert found;
			int count = rs.getInt(1);
			assert count <= 1;
			boolean more = rs.next();
			assert !more;
			rs.close();
			ps.close();
			return count > 0;
		} catch(SQLException e) {
			tryToClose(rs);
			tryToClose(ps);
			tryToClose(txn);
			throw new DbException(e);
		}
	}

	public Set<ContactId> getContacts(Connection txn) throws DbException {
		PreparedStatement ps = null;
		ResultSet rs = null;
		try {
			String sql = "SELECT contactId FROM contacts";
			ps = txn.prepareStatement(sql);
			rs = ps.executeQuery();
			Set<ContactId> ids = new HashSet<ContactId>();
			while(rs.next()) ids.add(new ContactId(rs.getInt(1)));
			rs.close();
			ps.close();
			return ids;
		} catch(SQLException e) {
			tryToClose(rs);
			tryToClose(ps);
			tryToClose(txn);
			throw new DbException(e);
		}
	}

	protected long getDiskSpace(File f) {
		long total = 0L;
		if(f.isDirectory()) {
			for(File child : f.listFiles()) total += getDiskSpace(child);
			return total;
		} else return f.length();
	}

	public Message getMessage(Connection txn, MessageId m) throws DbException {
		PreparedStatement ps = null;
		ResultSet rs = null;
		try {
			String sql =
				"SELECT parentId, groupId, authorId, timestamp, size, body"
				+ " FROM messages WHERE messageId = ?";
			ps = txn.prepareStatement(sql);
			ps.setBytes(1, m.getBytes());
			rs = ps.executeQuery();
			boolean found = rs.next();
			assert found;
			MessageId parent = new MessageId(rs.getBytes(1));
			GroupId group = new GroupId(rs.getBytes(2));
			AuthorId author = new AuthorId(rs.getBytes(3));
			long timestamp = rs.getLong(4);
			int size = rs.getInt(5);
			Blob b = rs.getBlob(6);
			byte[] body = b.getBytes(1, size);
			assert body.length == size;
			boolean more = rs.next();
			assert !more;
			rs.close();
			ps.close();
			return messageFactory.createMessage(m, parent, group, author,
					timestamp, body);
		} catch(SQLException e) {
			tryToClose(rs);
			tryToClose(ps);
			tryToClose(txn);
			throw new DbException(e);
		}
	}

	public Iterable<MessageId> getMessagesByAuthor(Connection txn, AuthorId a)
	throws DbException {
		PreparedStatement ps = null;
		ResultSet rs = null;
		try {
			String sql = "SELECT messageId FROM messages WHERE authorId = ?";
			ps = txn.prepareStatement(sql);
			ps.setBytes(1, a.getBytes());
			rs = ps.executeQuery();
			List<MessageId> ids = new ArrayList<MessageId>();
			while(rs.next()) ids.add(new MessageId(rs.getBytes(1)));
			rs.close();
			ps.close();
			return ids;
		} catch(SQLException e) {
			tryToClose(rs);
			tryToClose(ps);
			tryToClose(txn);
			throw new DbException(e);
		}
	}

	public Iterable<MessageId> getMessagesByParent(Connection txn, MessageId m)
	throws DbException {
		PreparedStatement ps = null;
		ResultSet rs = null;
		try {
			String sql = "SELECT messageId FROM messages WHERE parentId = ?";
			ps = txn.prepareStatement(sql);
			ps.setBytes(1, m.getBytes());
			rs = ps.executeQuery();
			List<MessageId> ids = new ArrayList<MessageId>();
			while(rs.next()) ids.add(new MessageId(rs.getBytes(1)));
			rs.close();
			ps.close();
			return ids;
		} catch(SQLException e) {
			tryToClose(rs);
			tryToClose(ps);
			tryToClose(txn);
			throw new DbException(e);
		}
	}

	public int getNumberOfMessages(Connection txn) throws DbException {
		PreparedStatement ps = null;
		ResultSet rs = null;
		try {
			String sql = "SELECT COUNT(messageId) FROM messages";
			ps = txn.prepareStatement(sql);
			rs = ps.executeQuery();
			boolean found = rs.next();
			assert found;
			int count = rs.getInt(1);
			boolean more = rs.next();
			assert !more;
			rs.close();
			ps.close();
			return count;
		} catch(SQLException e) {
			tryToClose(rs);
			tryToClose(ps);
			tryToClose(txn);
			throw new DbException(e);
		}
	}

	public Iterable<MessageId> getOldMessages(Connection txn, long capacity)
	throws DbException {
		PreparedStatement ps = null;
		ResultSet rs = null;
		try {
			String sql = "SELECT size, messageId FROM messages"
				+ " ORDER BY timestamp";
			ps = txn.prepareStatement(sql);
			rs = ps.executeQuery();
			List<MessageId> ids = new ArrayList<MessageId>();
			long total = 0L;
			while(rs.next()) {
				int size = rs.getInt(1);
				if(total + size > capacity) break;
				ids.add(new MessageId(rs.getBytes(2)));
				total += size;
			}
			rs.close();
			ps.close();
			if(LOG.isLoggable(Level.FINE))
				LOG.fine(ids.size() + " old messages, " + total + " bytes");
			return ids;
		} catch(SQLException e) {
			tryToClose(rs);
			tryToClose(ps);
			tryToClose(txn);
			throw new DbException(e);
		}
	}

	public MessageId getParent(Connection txn, MessageId m) throws DbException {
		PreparedStatement ps = null;
		ResultSet rs = null;
		try {
			String sql = "SELECT parentId FROM messages WHERE messageId = ?";
			ps = txn.prepareStatement(sql);
			ps.setBytes(1, m.getBytes());
			rs = ps.executeQuery();
			boolean found = rs.next();
			assert found;
			byte[] parent = rs.getBytes(1);
			boolean more = rs.next();
			assert !more;
			rs.close();
			ps.close();
			return new MessageId(parent);
		} catch(SQLException e) {
			tryToClose(rs);
			tryToClose(ps);
			tryToClose(txn);
			throw new DbException(e);
		}
	}

	public Rating getRating(Connection txn, AuthorId a) throws DbException {
		PreparedStatement ps = null;
		ResultSet rs = null;
		try {
			String sql = "SELECT rating FROM ratings WHERE authorId = ?";
			ps = txn.prepareStatement(sql);
			ps.setBytes(1, a.getBytes());
			rs = ps.executeQuery();
			Rating r;
			if(rs.next()) r = Rating.values()[rs.getByte(1)];
			else r = Rating.UNRATED;
			boolean more = rs.next();
			assert !more;
			rs.close();
			ps.close();
			return r;
		} catch(SQLException e) {
			tryToClose(rs);
			tryToClose(ps);
			tryToClose(txn);
			throw new DbException(e);
		}
	}

	public int getSendability(Connection txn, MessageId m) throws DbException {
		PreparedStatement ps = null;
		ResultSet rs = null;
		try {
			String sql = "SELECT sendability FROM messages WHERE messageId = ?";
			ps = txn.prepareStatement(sql);
			ps.setBytes(1, m.getBytes());
			rs = ps.executeQuery();
			boolean found = rs.next();
			assert found;
			int sendability = rs.getInt(1);
			boolean more = rs.next();
			assert !more;
			rs.close();
			ps.close();
			return sendability;
		} catch(SQLException e) {
			tryToClose(rs);
			tryToClose(ps);
			tryToClose(txn);
			throw new DbException(e);
		}
	}

	public Iterable<MessageId> getSendableMessages(Connection txn,
			ContactId c, long capacity) throws DbException {
		PreparedStatement ps = null;
		ResultSet rs = null;
		try {
			String sql = "SELECT size, messages.messageId FROM messages"
				+ " JOIN contactSubscriptions"
				+ " ON messages.groupId = contactSubscriptions.groupId"
				+ " JOIN statuses ON messages.messageId = statuses.messageId"
				+ " WHERE contactSubscriptions.contactId = ?"
				+ " AND statuses.contactId = ? AND status = ?"
				+ " AND sendability > ZERO()";
			ps = txn.prepareStatement(sql);
			ps.setInt(1, c.getInt());
			ps.setInt(2, c.getInt());
			ps.setShort(3, (short) Status.NEW.ordinal());
			rs = ps.executeQuery();
			List<MessageId> ids = new ArrayList<MessageId>();
			long total = 0;
			while(rs.next()) {
				int size = rs.getInt(1);
				if(total + size > capacity) break;
				ids.add(new MessageId(rs.getBytes(2)));
				total += size;
			}
			rs.close();
			ps.close();
			if(!ids.isEmpty()) {
				if(LOG.isLoggable(Level.FINE))
					LOG.fine(ids.size() + " sendable messages, " + total
							+ " bytes");
			}
			return ids;
		} catch(SQLException e) {
			tryToClose(rs);
			tryToClose(ps);
			tryToClose(txn);
			throw new DbException(e);
		}
	}

	public Set<GroupId> getSubscriptions(Connection txn) throws DbException {
		PreparedStatement ps = null;
		ResultSet rs = null;
		try {
			String sql = "SELECT groupId FROM localSubscriptions";
			ps = txn.prepareStatement(sql);
			rs = ps.executeQuery();
			Set<GroupId> ids = new HashSet<GroupId>();
			while(rs.next()) ids.add(new GroupId(rs.getBytes(1)));
			rs.close();
			ps.close();
			return ids;
		} catch(SQLException e) {
			tryToClose(rs);
			tryToClose(ps);
			tryToClose(txn);
			throw new DbException(e);
		}
	}

	public void removeAckedBatch(Connection txn, ContactId c, BatchId b)
	throws DbException {
		removeBatch(txn, c, b, Status.SEEN);
	}

	private void removeBatch(Connection txn, ContactId c, BatchId b,
			Status newStatus) throws DbException {
		PreparedStatement ps = null, ps1 = null;
		ResultSet rs = null;
		try {
			String sql = "SELECT messageId FROM outstandingMessages"
				+ " WHERE contactId = ? AND batchId = ?";
			ps = txn.prepareStatement(sql);
			ps.setInt(1, c.getInt());
			ps.setBytes(2, b.getBytes());
			rs = ps.executeQuery();
			sql = "UPDATE statuses SET status = ?"
				+ " WHERE messageId = ? AND contactId = ? AND status = ?";
			ps1 = txn.prepareStatement(sql);
			ps1.setShort(1, (short) newStatus.ordinal());
			ps1.setInt(3, c.getInt());
			ps1.setShort(4, (short) Status.SENT.ordinal());
			int messages = 0;
			while(rs.next()) {
				messages++;
				ps1.setBytes(2, rs.getBytes(1));
				ps1.addBatch();
			}
			rs.close();
			ps.close();
			int[] rowsAffected = ps1.executeBatch();
			assert rowsAffected.length == messages;
			for(int i = 0; i < rowsAffected.length; i++) {
				assert rowsAffected[i] <= 1;
			}
			ps1.close();
			// Cascade on delete
			sql = "DELETE FROM outstandingBatches WHERE batchId = ?";
			ps = txn.prepareStatement(sql);
			ps.setBytes(1, b.getBytes());
			int rowsAffected1 = ps.executeUpdate();
			assert rowsAffected1 <= 1;
			ps.close();
		} catch(SQLException e) {
			tryToClose(rs);
			tryToClose(ps);
			tryToClose(ps1);
			tryToClose(txn);
			throw new DbException(e);
		}
	}

	public Set<BatchId> removeBatchesToAck(Connection txn, ContactId c)
	throws DbException {
		PreparedStatement ps = null;
		ResultSet rs = null;
		try {
			String sql = "SELECT batchId FROM batchesToAck"
				+ " WHERE contactId = ?";
			ps = txn.prepareStatement(sql);
			ps.setInt(1, c.getInt());
			rs = ps.executeQuery();
			Set<BatchId> ids = new HashSet<BatchId>();
			while(rs.next()) ids.add(new BatchId(rs.getBytes(1)));
			rs.close();
			ps.close();
			sql = "DELETE FROM batchesToAck WHERE contactId = ?";
			ps = txn.prepareStatement(sql);
			ps.setInt(1, c.getInt());
			int rowsAffected = ps.executeUpdate();
			assert rowsAffected == ids.size();
			ps.close();
			return ids;
		} catch(SQLException e) {
			tryToClose(rs);
			tryToClose(ps);
			tryToClose(txn);
			throw new DbException(e);
		}
	}

	public void removeContact(Connection txn, ContactId c)
	throws DbException {
		PreparedStatement ps = null;
		try {
			String sql = "DELETE FROM contacts WHERE contactId = ?";
			ps = txn.prepareStatement(sql);
			ps.setInt(1, c.getInt());
			int rowsAffected = ps.executeUpdate();
			assert rowsAffected == 1;
			ps.close();
		} catch(SQLException e) {
			tryToClose(ps);
			tryToClose(txn);
			throw new DbException(e);
		}
	}

	public void removeLostBatch(Connection txn, ContactId c, BatchId b)
	throws DbException {
		removeBatch(txn, c, b, Status.NEW);
	}

	public void removeMessage(Connection txn, MessageId m) throws DbException {
		PreparedStatement ps = null;
		try {
			String sql = "DELETE FROM messages WHERE messageId = ?";
			ps = txn.prepareStatement(sql);
			ps.setBytes(1, m.getBytes());
			int rowsAffected = ps.executeUpdate();
			assert rowsAffected == 1;
			ps.close();
		} catch(SQLException e) {
			tryToClose(ps);
			tryToClose(txn);
			throw new DbException(e);
		}
	}

	public void removeSubscription(Connection txn, GroupId g)
	throws DbException {
		PreparedStatement ps = null;
		try {
			String sql = "DELETE FROM localSubscriptions WHERE groupId = ?";
			ps = txn.prepareStatement(sql);
			ps.setBytes(1, g.getBytes());
			int rowsAffected = ps.executeUpdate();
			assert rowsAffected == 1;
			ps.close();
		} catch(SQLException e) {
			tryToClose(ps);
			tryToClose(txn);
			throw new DbException(e);
		}
	}

	public Rating setRating(Connection txn, AuthorId a, Rating r)
	throws DbException {
		PreparedStatement ps = null;
		ResultSet rs = null;
		try {
			String sql = "SELECT rating FROM ratings WHERE authorId = ?";
			ps = txn.prepareStatement(sql);
			ps.setBytes(1, a.getBytes());
			rs = ps.executeQuery();
			Rating old;
			if(rs.next()) {
				old = Rating.values()[rs.getByte(1)];
				boolean more = rs.next();
				assert !more;
				rs.close();
				ps.close();
				sql = "UPDATE ratings SET rating = ? WHERE authorId = ?";
				ps = txn.prepareStatement(sql);
				ps.setShort(1, (short) r.ordinal());
				ps.setBytes(2, a.getBytes());
				int rowsAffected = ps.executeUpdate();
				assert rowsAffected == 1;
				ps.close();
			} else {
				rs.close();
				ps.close();
				old = Rating.UNRATED;
				sql = "INSERT INTO ratings (authorId, rating) VALUES (?, ?)";
				ps = txn.prepareStatement(sql);
				ps.setBytes(1, a.getBytes());
				ps.setShort(2, (short) r.ordinal());
				int rowsAffected = ps.executeUpdate();
				assert rowsAffected == 1;
				ps.close();
			}
			return old;
		} catch(SQLException e) {
			tryToClose(rs);
			tryToClose(ps);
			tryToClose(txn);
			throw new DbException(e);
		}
	}

	public void setSendability(Connection txn, MessageId m, int sendability)
	throws DbException {
		PreparedStatement ps = null;
		try {
			String sql = "UPDATE messages SET sendability = ?"
				+ " WHERE messageId = ?";
			ps = txn.prepareStatement(sql);
			ps.setInt(1, sendability);
			ps.setBytes(2, m.getBytes());
			int rowsAffected = ps.executeUpdate();
			assert rowsAffected == 1;
			ps.close();
		} catch(SQLException e) {
			tryToClose(ps);
			tryToClose(txn);
			throw new DbException(e);
		}
	}

	public void setStatus(Connection txn, ContactId c, MessageId m, Status s)
	throws DbException {
		PreparedStatement ps = null;
		ResultSet rs = null;
		try {
			String sql = "SELECT status FROM statuses"
				+ " WHERE messageId = ? AND contactId = ?";
			ps = txn.prepareStatement(sql);
			ps.setBytes(1, m.getBytes());
			ps.setInt(2, c.getInt());
			rs = ps.executeQuery();
			if(rs.next()) {
				Status old = Status.values()[rs.getByte(1)];
				boolean more = rs.next();
				assert !more;
				rs.close();
				ps.close();
				if(!old.equals(Status.SEEN) && !old.equals(s)) {
					sql = "UPDATE statuses SET status = ?"
						+ " WHERE messageId = ? AND contactId = ?";
					ps = txn.prepareStatement(sql);
					ps.setShort(1, (short) s.ordinal());
					ps.setBytes(2, m.getBytes());
					ps.setInt(3, c.getInt());
					int rowsAffected = ps.executeUpdate();
					assert rowsAffected == 1;
					ps.close();
				}
			} else {
				rs.close();
				ps.close();
				sql = "INSERT INTO statuses (messageId, contactId, status)"
					+ " VALUES (?, ?, ?)";
				ps = txn.prepareStatement(sql);
				ps.setBytes(1, m.getBytes());
				ps.setInt(2, c.getInt());
				ps.setShort(3, (short) s.ordinal());
				int rowsAffected = ps.executeUpdate();
				assert rowsAffected == 1;
				ps.close();
			}
		} catch(SQLException e) {
			tryToClose(rs);
			tryToClose(ps);
			tryToClose(txn);
			throw new DbException(e);
		}
	}
}
