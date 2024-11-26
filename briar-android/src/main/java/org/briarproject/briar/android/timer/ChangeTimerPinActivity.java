package org.briarproject.briar.android.timer;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.KeyEvent;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import com.google.android.material.textfield.TextInputLayout;

import org.briarproject.bramble.api.crypto.DecryptionResult;
import org.briarproject.briar.R;
import org.briarproject.briar.android.activity.ActivityComponent;
import org.briarproject.briar.android.activity.BriarActivity;
import org.briarproject.briar.android.viewmodel.LiveEvent;
import org.briarproject.briar.android.viewmodel.MutableLiveEvent;

import javax.inject.Inject;

import androidx.annotation.VisibleForTesting;
import androidx.lifecycle.ViewModelProvider;

import static android.view.View.INVISIBLE;
import static android.view.View.VISIBLE;
import static android.widget.Toast.LENGTH_LONG;
import static org.briarproject.bramble.api.crypto.DecryptionResult.INVALID_PASSWORD;
import static org.briarproject.bramble.api.crypto.DecryptionResult.SUCCESS;
import static org.briarproject.briar.android.util.UiUtils.hideSoftKeyboard;
import static org.briarproject.briar.android.util.UiUtils.setError;
import static org.briarproject.briar.android.util.UiUtils.showSoftKeyboard;

public class ChangeTimerPinActivity extends BriarActivity
		implements View.OnClickListener, TextView.OnEditorActionListener {

	@Inject
	ViewModelProvider.Factory viewModelFactory;

	private TextInputLayout currentPasswordEntryWrapper;
	private TextInputLayout newPasswordEntryWrapper;
	private TextInputLayout newPasswordConfirmationWrapper;
	private EditText currentPassword;
	private EditText newPassword;
	private EditText newPasswordConfirmation;
	private Button changePasswordButton;
	private ProgressBar progress;

	@VisibleForTesting
	ChangeTimerPinViewModel viewModel;

	@Override
	public void injectActivity(ActivityComponent component) {
		component.inject(this);
		viewModel = new ViewModelProvider(this, viewModelFactory)
				.get(ChangeTimerPinViewModel.class);
	}

	@Override
	public void onCreate(Bundle state) {
		super.onCreate(state);
		setContentView(R.layout.activity_change_timer_pin);

		SharedPreferences sharedPref = getSharedPreferences(
				getString(R.string.timer_preference), Context.MODE_PRIVATE);

		int oldPin = sharedPref.getInt(getString(R.string.timer_current_pin), 0);

		currentPasswordEntryWrapper =
				findViewById(R.id.current_password_entry_wrapper);
		newPasswordEntryWrapper = findViewById(R.id.new_password_entry_wrapper);
		newPasswordConfirmationWrapper =
				findViewById(R.id.new_password_confirm_wrapper);
		currentPassword = findViewById(R.id.current_password_entry);
		newPassword = findViewById(R.id.new_password_entry);
		newPasswordConfirmation = findViewById(R.id.new_password_confirm);
		changePasswordButton = findViewById(R.id.change_password);
		progress = findViewById(R.id.progress_wheel);

		if (oldPin == 0) {
			currentPassword.setText("0");
			currentPasswordEntryWrapper.setVisibility(View.GONE);
		}

		TextWatcher tw = new TextWatcher() {
			@Override
			public void beforeTextChanged(CharSequence s, int start, int count,
					int after) {
			}

			@Override
			public void onTextChanged(CharSequence s, int start, int before,
					int count) {
				enableOrDisableContinueButton();
			}

			@Override
			public void afterTextChanged(Editable s) {
			}
		};

		currentPassword.addTextChangedListener(tw);
		newPassword.addTextChangedListener(tw);
		newPasswordConfirmation.addTextChangedListener(tw);
		newPasswordConfirmation.setOnEditorActionListener(this);
		changePasswordButton.setOnClickListener(this);
	}

	@Override
	public boolean onOptionsItemSelected(MenuItem item) {
		if (item.getItemId() == android.R.id.home) {
			onBackPressed();
			return true;
		}
		return super.onOptionsItemSelected(item);
	}

	private void enableOrDisableContinueButton() {
		if (progress == null) return; // Not created yet

		String firstPassword = newPassword.getText().toString();
		String secondPassword = newPasswordConfirmation.getText().toString();
		boolean passwordsMatch = firstPassword.equals(secondPassword);

		boolean allowedCharCount = firstPassword.length() < 7;

		setError(newPasswordConfirmationWrapper, getString(R.string.pin_max_count), !allowedCharCount);

		setError(newPasswordConfirmationWrapper,
				getString(R.string.passwords_do_not_match),
				secondPassword.length() > 0 && !passwordsMatch);
		changePasswordButton.setEnabled(
				!currentPassword.getText().toString().isEmpty() &&
						!firstPassword.isEmpty() &&
						passwordsMatch && allowedCharCount);
	}

	@Override
	public boolean onEditorAction(TextView v, int actionId, KeyEvent event) {
		hideSoftKeyboard(v);
		return true;
	}

	@Override
	public void onClick(View view) {
		// Replace the button with a progress bar
		changePasswordButton.setVisibility(INVISIBLE);
		progress.setVisibility(VISIBLE);

		int curPwd = Integer.parseInt(currentPassword.getText().toString());
		int newPwd = Integer.parseInt(newPassword.getText().toString());

		changePassword(curPwd, newPwd).observeEvent(this, result -> {
					if (result.equals(String.valueOf(SUCCESS))) {
						Toast.makeText(
								this,
								R.string.password_changed,
								LENGTH_LONG).show();
						setResult(RESULT_OK);
						supportFinishAfterTransition();
					} else {
						tryAgain(result);
					}
				}
		);
	}

	private void tryAgain(String result) {
		changePasswordButton.setVisibility(VISIBLE);
		progress.setVisibility(INVISIBLE);
		setError(currentPasswordEntryWrapper,
				getString(R.string.try_again), true);
		currentPassword.setText("");
		// show the keyboard again
		showSoftKeyboard(currentPassword);
	}

	private void changePin(int oldPassword, int newPassword) throws Exception {
		SharedPreferences sharedPref = getSharedPreferences(
				getString(R.string.timer_preference), Context.MODE_PRIVATE);

		SharedPreferences.Editor editor = sharedPref.edit();

		int oldPin = sharedPref.getInt(getString(R.string.timer_current_pin), 0);

		if(oldPin != 0 && oldPassword != oldPin) {
			throw new Exception(String.valueOf(INVALID_PASSWORD));
		}
		//change password
		editor.putInt(getString(R.string.timer_current_pin), newPassword).apply();
	}

	LiveEvent<String> changePassword(int oldPassword,
			int newPassword) {
		MutableLiveEvent<String> result = new MutableLiveEvent<>();
		//change timer pin password
		try {
			this.changePin(oldPassword, newPassword);
			result.postEvent(String.valueOf(SUCCESS));
		} catch (Exception e) {
			result.postEvent(e.getLocalizedMessage());
		}


		return result;
	}
}

