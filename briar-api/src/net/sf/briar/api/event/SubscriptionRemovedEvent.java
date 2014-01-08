package net.sf.briar.api.event;

import net.sf.briar.api.messaging.Group;

/** An event that is broadcast when the user unsubscribes from a group. */
public class SubscriptionRemovedEvent extends Event {

	private final Group group;

	public SubscriptionRemovedEvent(Group group) {
		this.group = group;
	}

	public Group getGroup() {
		return group;
	}
}