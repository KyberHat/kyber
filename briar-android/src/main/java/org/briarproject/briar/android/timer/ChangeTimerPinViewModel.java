package org.briarproject.briar.android.timer;

import android.content.Context;
import android.content.SharedPreferences;

import org.briarproject.bramble.api.account.AccountManager;
import org.briarproject.bramble.api.crypto.DecryptionException;
import org.briarproject.bramble.api.crypto.DecryptionResult;
import org.briarproject.bramble.api.lifecycle.IoExecutor;
import org.briarproject.briar.R;
import org.briarproject.briar.android.viewmodel.LiveEvent;
import org.briarproject.briar.android.viewmodel.MutableLiveEvent;

import java.util.concurrent.Executor;

import javax.inject.Inject;

import androidx.lifecycle.ViewModel;


public class ChangeTimerPinViewModel extends ViewModel {

	private final Executor ioExecutor;

	@Inject
	ChangeTimerPinViewModel(@IoExecutor Executor ioExecutor) {
		this.ioExecutor = ioExecutor;
	}


}
