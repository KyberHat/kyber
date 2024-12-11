package org.briarproject.briar.android.privategroup.conversation;

import org.briarproject.bramble.api.identity.Author;
import org.briarproject.briar.api.attachment.AttachmentHeader;
import org.briarproject.briar.api.identity.AuthorInfo;
import org.briarproject.bramble.api.sync.GroupId;
import org.briarproject.bramble.api.sync.MessageId;
import org.briarproject.briar.R;
import org.briarproject.briar.android.threaded.ThreadItem;
import org.briarproject.briar.api.privategroup.GroupMessageHeader;

import java.util.List;

import javax.annotation.Nullable;
import javax.annotation.concurrent.NotThreadSafe;

import androidx.annotation.LayoutRes;
import androidx.annotation.UiThread;

@UiThread
@NotThreadSafe
public class GroupMessageItem extends ThreadItem {

	private final GroupId groupId;
	private final List<AttachmentHeader> headers;

	private GroupMessageItem(MessageId messageId, GroupId groupId,
			@Nullable MessageId parentId, String text, long timestamp,
			Author author, AuthorInfo authorInfo, boolean isRead, List<AttachmentHeader> headers) {
		super(messageId, parentId, text, timestamp, author, authorInfo, isRead);
		this.groupId = groupId;
		this.headers = headers;
	}

	GroupMessageItem(GroupMessageHeader h, String text, List<AttachmentHeader> headers) {
		this(h.getId(), h.getGroupId(), h.getParentId(), text, h.getTimestamp(),
				h.getAuthor(), h.getAuthorInfo(), h.isRead(), headers);
	}

	public GroupId getGroupId() {
		return groupId;
	}

	public List<AttachmentHeader> getHeaders() {
		return headers;
	}

	@LayoutRes
	public int getLayout() {
		return R.layout.list_item_thread;
	}

}
