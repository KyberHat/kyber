package org.briarproject.briar.android.threaded;
import android.view.View;
import android.widget.TextView;

import org.briarproject.briar.R;
import org.briarproject.briar.android.privategroup.conversation.GroupMessageItem;
import org.briarproject.briar.android.threaded.ThreadItemAdapter.ThreadItemListener;
import org.briarproject.briar.api.attachment.AttachmentHeader;
import org.briarproject.nullsafety.NotNullByDefault;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import androidx.annotation.UiThread;
import androidx.constraintlayout.widget.ConstraintSet;
import androidx.recyclerview.widget.RecyclerView;
import androidx.recyclerview.widget.StaggeredGridLayoutManager;

import static android.view.View.GONE;
import static android.view.View.VISIBLE;
import static androidx.constraintlayout.widget.ConstraintSet.WRAP_CONTENT;
import static org.briarproject.onionwrapper.TorWrapper.LOG;

@UiThread
@NotNullByDefault
public class ThreadPostViewHolder<I extends ThreadItem>
		extends BaseThreadItemViewHolder<I> {

	private final TextView  lvlText;
	private final View[] lvls;
	private final View replyButton;
	private final RecyclerView imageRecyclerView;
	private final ConstraintSet imageConstraints = new ConstraintSet();
	private final ConstraintSet imageTextConstraints = new ConstraintSet();

	private final static int[] nestedLineIds = {
			R.id.nested_line_1, R.id.nested_line_2, R.id.nested_line_3,
			R.id.nested_line_4, R.id.nested_line_5
	};

	public ThreadPostViewHolder(View v) {
		super(v);

		lvlText = v.findViewById(R.id.nested_line_text);
		lvls = new View[nestedLineIds.length];
		for (int i = 0; i < lvls.length; i++) {
			lvls[i] = v.findViewById(nestedLineIds[i]);
		}
		replyButton = v.findViewById(R.id.btn_reply);

		imageRecyclerView = v.findViewById(R.id.nestedImageList);
		imageConstraints.clone(v.getContext(),
				R.layout.list_item_conversation_msg_image);
		imageTextConstraints.clone(v.getContext(),
				R.layout.list_item_conversation_msg_image_text);
	}

	@Override
	public void bind(I item, ThreadItemListener<I> listener) {
		super.bind(item, listener);
		GroupMessageItem groupMessageItem = (GroupMessageItem) item;
		if (groupMessageItem.getHeaders() != null) {
			LOG.info("image-test: -> groupMessageItem.getHeaders() != null");
			if (groupMessageItem.getHeaders().isEmpty()) {
				LOG.info("image-test: -> groupMessageItem.getHeaders() isEmpty");
				for (int i = 0; i < lvls.length; i++) {
					lvls[i].setVisibility(i < item.getLevel() ? VISIBLE : GONE);
				}
				if (item.getLevel() > 5) {
					lvlText.setVisibility(VISIBLE);
					lvlText.setText(
							String.format(Locale.getDefault(), "%d", item.getLevel()));
				} else {
					lvlText.setVisibility(GONE);
				}
			} else {
				LOG.info("image-test: -> groupMessageItem.getHeaders() notEmpty");
				bindImageItem((GroupMessageItem) item);
			}
		} else {
			LOG.info("image-test: -> groupMessageItem.getHeaders() == null");
			for (int i = 0; i < lvls.length; i++) {
				lvls[i].setVisibility(i < item.getLevel() ? VISIBLE : GONE);
			}
			if (item.getLevel() > 5) {
				lvlText.setVisibility(VISIBLE);
				lvlText.setText(
						String.format(Locale.getDefault(), "%d", item.getLevel()));
			} else {
				lvlText.setVisibility(GONE);
			}
		}

		replyButton.setOnClickListener(v -> listener.onReplyClick(item));
	}

	private void bindImageItem(GroupMessageItem item) {
		List<AttachmentHeader> imageAttachments = item.getHeaders();

		if (imageAttachments != null && !imageAttachments.isEmpty()) {
			// Show the RecyclerView with images
			ImageAdapter imageAdapter = new ImageAdapter(getContext()); // Pass the image attachments to the adapter
			imageAdapter.setGroupMessageItem(item);
			imageRecyclerView.setAdapter(imageAdapter);
			imageRecyclerView.setVisibility(VISIBLE);

			// Set up the LayoutManager if not already set
			if (imageRecyclerView.getLayoutManager() == null) {
				StaggeredGridLayoutManager layoutManager = new StaggeredGridLayoutManager(2, StaggeredGridLayoutManager.VERTICAL);
				imageRecyclerView.setLayoutManager(layoutManager);
			}
		} else {
			// If no images, hide the RecyclerView
			imageRecyclerView.setVisibility(GONE);
		}
	}
}
