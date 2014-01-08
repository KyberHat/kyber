package net.sf.briar.api.event;

import net.sf.briar.api.AuthorId;

/** An event that is broadcast when a local pseudonym is added. */
public class LocalAuthorAddedEvent extends Event {

	private final AuthorId authorId;

	public LocalAuthorAddedEvent(AuthorId authorId) {
		this.authorId = authorId;
	}

	public AuthorId getAuthorId() {
		return authorId;
	}
}