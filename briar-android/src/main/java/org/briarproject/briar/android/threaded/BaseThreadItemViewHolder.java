package org.briarproject.briar.android.threaded;

import android.animation.Animator;
import android.animation.ArgbEvaluator;
import android.animation.ValueAnimator;
import android.content.Context;
import android.text.util.Linkify;
import android.view.View;
import android.view.ViewGroup;
import android.view.animation.AccelerateInterpolator;
import android.widget.TextView;

import org.briarproject.bramble.util.StringUtils;
import org.briarproject.briar.R;
import org.briarproject.briar.android.privategroup.conversation.GroupMessageItem;
import org.briarproject.briar.android.threaded.ThreadItemAdapter.ThreadItemListener;
import org.briarproject.briar.android.view.AuthorView;
import org.briarproject.briar.api.attachment.AttachmentHeader;
import org.briarproject.nullsafety.NotNullByDefault;

import java.util.List;

import androidx.annotation.CallSuper;
import androidx.annotation.UiThread;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.constraintlayout.widget.ConstraintSet;
import androidx.recyclerview.widget.RecyclerView;
import androidx.recyclerview.widget.StaggeredGridLayoutManager;

import static android.view.View.GONE;
import static android.view.View.VISIBLE;
import static androidx.constraintlayout.widget.ConstraintSet.WRAP_CONTENT;
import static androidx.core.content.ContextCompat.getColor;
import static org.briarproject.briar.android.util.UiUtils.makeLinksClickable;

@UiThread
@NotNullByDefault
public abstract class BaseThreadItemViewHolder<I extends ThreadItem>
		extends RecyclerView.ViewHolder {

	private final static int ANIMATION_DURATION = 5000;

	protected final TextView textView;
	protected final RecyclerView imageList;
	protected final ConstraintLayout layout;
	private final AuthorView author;
	private final ConstraintSet imageConstraints = new ConstraintSet();
	private final ConstraintSet imageTextConstraints = new ConstraintSet();

	public BaseThreadItemViewHolder(View v) {
		super(v);

		layout = v.findViewById(R.id.layout);
		textView = v.findViewById(R.id.text);
		author = v.findViewById(R.id.author);
		imageList = v.findViewById(R.id.imageList);

		imageConstraints.clone(v.getContext(),
				R.layout.list_item_conversation_msg_image);
		imageTextConstraints.clone(v.getContext(),
				R.layout.list_item_conversation_msg_image_text);
	}

	@CallSuper
	public void bind(I item, ThreadItemListener<I> listener) {
		if (item.getText() != null) {
			textView.setText(StringUtils.trim(item.getText()));
		}
		Linkify.addLinks(textView, Linkify.WEB_URLS);
		makeLinksClickable(textView, listener::onLinkClick);

		author.setAuthor(item.getAuthor(), item.getAuthorInfo());
		author.setDate(item.getTimestamp());
		if (item.isHighlighted()) {
			layout.setActivated(true);
		} else if (!item.isRead()) {
			layout.setActivated(true);
			animateFadeOut();
		} else {
			layout.setActivated(false);
		}
	}

	private void animateFadeOut() {
		setIsRecyclable(false);
		ValueAnimator anim = new ValueAnimator();
		int viewColor = getColor(getContext(), R.color.thread_item_highlight);
		anim.setIntValues(viewColor,
				getColor(getContext(), R.color.thread_item_background));
		anim.setEvaluator(new ArgbEvaluator());
		anim.setInterpolator(new AccelerateInterpolator());
		anim.addListener(new Animator.AnimatorListener() {
			@Override
			public void onAnimationStart(Animator animation) {
			}
			@Override
			public void onAnimationEnd(Animator animation) {
				layout.setBackgroundResource(
						R.drawable.list_item_thread_background);
				layout.setActivated(false);
				setIsRecyclable(true);
			}
			@Override
			public void onAnimationCancel(Animator animation) {
			}
			@Override
			public void onAnimationRepeat(Animator animation) {
			}
		});
		anim.addUpdateListener(valueAnimator -> layout.setBackgroundColor(
				(Integer) valueAnimator.getAnimatedValue()));
		anim.setDuration(ANIMATION_DURATION);
		anim.start();
	}

	protected Context getContext() {
		return textView.getContext();
	}

	private void bindImageItem(GroupMessageItem item) {
		List<AttachmentHeader> imageAttachments = item.getHeaders();

		if (imageAttachments != null && !imageAttachments.isEmpty()) {
			// Show the RecyclerView with images
			RecyclerView imageRecyclerView = layout.findViewById(R.id.imageList);
			imageRecyclerView.setVisibility(VISIBLE);

			ImageAdapter imageAdapter = new ImageAdapter(getContext()); // Pass the image attachments to the adapter
			imageRecyclerView.setAdapter(imageAdapter);

			// Set up the LayoutManager if not already set
			if (imageRecyclerView.getLayoutManager() == null) {
				StaggeredGridLayoutManager layoutManager = new StaggeredGridLayoutManager(2, StaggeredGridLayoutManager.VERTICAL);
				imageRecyclerView.setLayoutManager(layoutManager);
			}

			// Apply the appropriate constraints based on whether text is present
			ConstraintSet
					constraintSet = (item.getText() == null) ? imageConstraints : imageTextConstraints;
			constraintSet.constrainWidth(R.id.imageList, WRAP_CONTENT);
			constraintSet.constrainHeight(R.id.imageList, WRAP_CONTENT);
			constraintSet.applyTo(layout);

			imageAdapter.setGroupMessageItem(item);
		} else {
			// If no images, hide the RecyclerView
			layout.findViewById(R.id.imageList).setVisibility(GONE);
		}
	}
}
