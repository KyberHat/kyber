package org.briarproject.briar.api.privategroup;

import org.briarproject.bramble.api.identity.Author;
import org.briarproject.bramble.api.sync.GroupId;
import org.briarproject.bramble.api.sync.MessageId;
import org.briarproject.briar.api.attachment.AttachmentHeader;
import org.briarproject.briar.api.client.PostHeader;
import org.briarproject.briar.api.identity.AuthorInfo;
import org.briarproject.nullsafety.NotNullByDefault;

import java.util.List;

import javax.annotation.Nullable;
import javax.annotation.concurrent.Immutable;

@Immutable
@NotNullByDefault
public class GroupMessageHeader extends PostHeader {

	private final GroupId groupId;
	@Nullable
	private final List<AttachmentHeader> attachmentHeaders;

	public GroupMessageHeader(GroupId groupId, MessageId id,
			@Nullable MessageId parentId, long timestamp,
			Author author, AuthorInfo authorInfo, boolean read, @Nullable List<AttachmentHeader> attachmentHeaders) {
		super(id, parentId, timestamp, author, authorInfo, read);
		this.groupId = groupId;
		this.attachmentHeaders = attachmentHeaders;
	}

	public GroupId getGroupId() {
		return groupId;
	}

	@Nullable
	public List<AttachmentHeader> getAttachmentHeaders() {
		return attachmentHeaders;
	}

}
