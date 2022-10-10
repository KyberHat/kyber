package org.briarproject.bramble.mailbox;

import org.briarproject.bramble.api.contact.ContactId;
import org.briarproject.bramble.api.contact.ContactManager;
import org.briarproject.bramble.api.crypto.SecretKey;
import org.briarproject.bramble.api.db.DbException;
import org.briarproject.bramble.api.identity.Author;
import org.briarproject.bramble.api.identity.AuthorFactory;
import org.briarproject.bramble.api.identity.LocalAuthor;
import org.briarproject.bramble.api.mailbox.MailboxProperties;
import org.briarproject.mailbox.lib.TestMailbox;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import static org.briarproject.bramble.mailbox.MailboxIntegrationTestUtils.createMailboxApi;
import static org.briarproject.bramble.mailbox.MailboxIntegrationTestUtils.retryUntilSuccessOrTimeout;
import static org.briarproject.bramble.test.TestUtils.getSecretKey;
import static org.junit.Assert.assertEquals;

public class OwnMailboxContactListWorkerIntegrationTest
		extends AbstractMailboxIntegrationTest {

	@Rule
	public TemporaryFolder mailboxDataDirectory = new TemporaryFolder();

	private TestMailbox mailbox;

	private final MailboxApi api = createMailboxApi();

	private MailboxProperties ownerProperties;

	private LocalAuthor localAuthor1;

	private final SecretKey rootKey = getSecretKey();
	private final long timestamp = System.currentTimeMillis();

	@Before
	public void setUp() throws Exception {
		mailbox = new TestMailbox(mailboxDataDirectory.getRoot());
		mailbox.startLifecycle();

		c1 = startTestComponent(dir1, "Alice");
		localAuthor1 = c1.getIdentityManager().getLocalAuthor();

		ownerProperties = pair(c1, mailbox);
	}

	@After
	public void tearDown() {
		mailbox.stopLifecycle(true);
	}

	@Test
	public void testUploadContacts() throws Exception {
		// Check the initial conditions
		ContactManager contactManager = c1.getContactManager();
		assertEquals(0, contactManager.getPendingContacts().size());
		assertEquals(0, contactManager.getContacts().size());

		int numContactsToAdd = 5;
		List<ContactId> expectedContacts = createContacts(c1, numContactsToAdd);

		// Check for number of contacts on mailbox via API every 100ms
		retryUntilSuccessOrTimeout(1000, 100, () -> {
			Collection<ContactId> contacts = api.getContacts(ownerProperties);
			if (contacts.size() == numContactsToAdd) {
				assertEquals(expectedContacts, contacts);
				return true;
			}
			return false;
		});
	}

	private List<ContactId> createContacts(
			MailboxIntegrationTestComponent component, int numContacts)
			throws DbException {
		List<ContactId> contactIds = new ArrayList<>();
		ContactManager contactManager = component.getContactManager();
		AuthorFactory authorFactory = component.getAuthorFactory();
		for (int i = 0; i < numContacts; i++) {
			Author remote = authorFactory.createLocalAuthor("Bob " + i);
			ContactId c = contactManager.addContact(remote,
					localAuthor1.getId(), rootKey, timestamp, true, true, true);
			contactIds.add(c);
		}
		return contactIds;
	}
}
