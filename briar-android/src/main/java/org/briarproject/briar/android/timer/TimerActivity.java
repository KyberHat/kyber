package org.briarproject.briar.android.timer;

import android.content.Intent;
import android.os.Bundle;

import org.briarproject.briar.R;
import org.briarproject.briar.android.account.SetupActivity;
import org.briarproject.briar.android.activity.ActivityComponent;
import org.briarproject.briar.android.activity.BaseActivity;
import org.briarproject.briar.android.fragment.BaseFragment;

import javax.inject.Inject;

import androidx.annotation.Nullable;
import androidx.lifecycle.ViewModelProvider;

import static android.content.Intent.FLAG_ACTIVITY_CLEAR_TASK;
import static android.content.Intent.FLAG_ACTIVITY_CLEAR_TOP;
import static android.content.Intent.FLAG_ACTIVITY_NEW_TASK;
import static android.content.Intent.FLAG_ACTIVITY_TASK_ON_HOME;
import static org.briarproject.briar.android.timer.TimerViewModel.State.PIN_VALID;
import static org.briarproject.briar.android.timer.TimerViewModel.State.SIGNED_OUT;
import static org.briarproject.briar.android.timer.TimerViewModel.State.SIGNING_IN;
import  org.briarproject.briar.android.timer.ChangeTimerPinActivity;
import  org.briarproject.briar.android.timer.TimerPinFragment;
import  org.briarproject.briar.android.timer.TimerPinModule;
import  org.briarproject.briar.android.timer.TimerViewModel;


public class TimerActivity extends BaseActivity implements
		BaseFragment.BaseFragmentListener {

	@Inject
	ViewModelProvider.Factory viewModelFactory;

	private TimerViewModel viewModel;

	@Override
	public void injectActivity(ActivityComponent component) {
		component.inject(this);
		viewModel = new ViewModelProvider(this, viewModelFactory)
				.get(TimerViewModel.class);
	}

	@Override
	public void onCreate(@Nullable Bundle state) {
		super.onCreate(state);
		// fade-in after splash screen instead of default animation
		overridePendingTransition(R.anim.fade_in, R.anim.fade_out);

		setContentView(R.layout.activity_fragment_container);

		viewModel.getAccountDeleted().observeEvent(this, deleted -> {
			if (deleted) onAccountDeleted();
		});
		viewModel.getState().observe(this, this::onStateChanged);
	}

	@Override
	public void onStart() {
		super.onStart();
	}

	@Override
	public void onBackPressed() {
		// Move task and activity to the background instead of showing another
		// password prompt.
		// onActivityResult() won't be called in BriarActivity
		moveTaskToBack(true);
	}

	private void onStateChanged(TimerViewModel.State state) {
		if (state == SIGNED_OUT) {
			setResult(RESULT_OK);
			finish();
		} else if (state == SIGNING_IN){
			// Configuration changes such as screen rotation
			// can cause this to get called again.
			// Don't replace the fragment in that case to not lose view state.
			if (!isFragmentAdded(TimerPinFragment.TAG)) {
				showInitialFragment(new TimerPinFragment());
			}
		} else if (state == PIN_VALID) {
			setResult(RESULT_OK);
			finish();
		}
	}

	private void onAccountDeleted() {
		setResult(RESULT_CANCELED);
		finish();
		Intent i = new Intent(this, SetupActivity.class);
		i.addFlags(FLAG_ACTIVITY_NEW_TASK | FLAG_ACTIVITY_CLEAR_TOP |
				FLAG_ACTIVITY_CLEAR_TASK | FLAG_ACTIVITY_TASK_ON_HOME);
		startActivity(i);
	}

	@Override
	public void runOnDbThread(Runnable runnable) {
		// we don't need this and shouldn't be forced to implement it
		throw new UnsupportedOperationException();
	}
}
