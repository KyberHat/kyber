package org.briarproject.briar.android.timer;

import android.app.Application;
import android.content.Context;
import android.content.SharedPreferences;
import android.util.Log;

import org.briarproject.bramble.api.account.AccountManager;
import org.briarproject.bramble.api.crypto.DecryptionException;
import org.briarproject.bramble.api.crypto.DecryptionResult;
import org.briarproject.bramble.api.event.Event;
import org.briarproject.bramble.api.event.EventBus;
import org.briarproject.bramble.api.event.EventListener;
import org.briarproject.bramble.api.lifecycle.IoExecutor;
import org.briarproject.bramble.api.lifecycle.LifecycleManager;
import org.briarproject.bramble.api.lifecycle.event.LifecycleEvent;
import org.briarproject.briar.R;
import org.briarproject.briar.android.viewmodel.LiveEvent;
import org.briarproject.briar.android.viewmodel.MutableLiveEvent;
import org.briarproject.briar.api.android.AndroidNotificationManager;

import java.util.concurrent.Executor;

import javax.inject.Inject;

import androidx.annotation.UiThread;
import androidx.lifecycle.AndroidViewModel;
import androidx.lifecycle.LiveData;
import androidx.lifecycle.MutableLiveData;

import static org.briarproject.bramble.api.lifecycle.LifecycleManager.LifecycleState.COMPACTING_DATABASE;
import static org.briarproject.bramble.api.lifecycle.LifecycleManager.LifecycleState.MIGRATING_DATABASE;
import static org.briarproject.bramble.api.lifecycle.LifecycleManager.LifecycleState.STARTING_SERVICES;
import static org.briarproject.briar.android.timer.TimerViewModel.State.SIGNED_OUT;
import static org.briarproject.briar.android.timer.TimerViewModel.State.SIGNING_IN;
import static org.briarproject.briar.android.timer.TimerViewModel.State.STARTING;

public class TimerViewModel extends AndroidViewModel
		implements EventListener {

	enum State { STARTING, SIGNED_OUT, SIGNING_IN, PIN_VALID}

	private final EventBus eventBus;


	private final MutableLiveEvent<DecryptionResult> passwordValidated =
			new MutableLiveEvent<>();
	private final MutableLiveEvent<Boolean> accountDeleted =
			new MutableLiveEvent<>();
	private final MutableLiveData<State>
			state = new MutableLiveData<>();

	private int currentPin = 0;

	@Inject
	TimerViewModel(Application app,
			LifecycleManager lifecycleManager,
			EventBus eventBus) {
		super(app);
		this.eventBus = eventBus;

		SharedPreferences sharedPref = app.getSharedPreferences(
				app.getString(R.string.timer_preference), Context.MODE_PRIVATE);

		currentPin = sharedPref.getInt(app.getString(R.string.timer_current_pin), 0);

		updateState(lifecycleManager.getLifecycleState());
		eventBus.addListener(this);


	}

	@Override
	protected void onCleared() {
		eventBus.removeListener(this);
	}

	@Override
	public void eventOccurred(Event e) {
		if (e instanceof LifecycleEvent) {
			LifecycleManager.LifecycleState s = ((LifecycleEvent) e).getLifecycleState();
			updateState(s);
		}
	}

	@UiThread
	private void updateState(LifecycleManager.LifecycleState s) {

		if (hasSetPin()) {
			Log.e("TAGG", "state SIGNING_IN");
			state.setValue(SIGNING_IN);
		} else {
			Log.e("TAGG", "state SIGNED_OUT");
			state.setValue(SIGNED_OUT);
		}
	}

	private boolean hasSetPin(){
		return currentPin != 0;
	}

	void validatePassword(String password) {
		if (Integer.parseInt(password) == currentPin) {
			state.postValue(State.PIN_VALID);
		} else {
			passwordValidated.postEvent(DecryptionResult.INVALID_PASSWORD);
		}

	}

	LiveEvent<DecryptionResult> getPasswordValidated() {
		return passwordValidated;
	}

	LiveEvent<Boolean> getAccountDeleted() {
		return accountDeleted;
	}

	LiveData<State> getState() {
		return state;
	}

}

