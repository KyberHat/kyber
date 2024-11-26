package org.briarproject.briar.android.timer;

import android.os.Bundle;
import android.os.CountDownTimer;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.GridLayout;
import android.widget.ProgressBar;
import android.widget.TextView;


import org.briarproject.bramble.api.crypto.DecryptionResult;

import org.briarproject.briar.R;
import org.briarproject.briar.android.activity.ActivityComponent;
import org.briarproject.briar.android.fragment.BaseFragment;

import javax.annotation.Nullable;
import javax.inject.Inject;

import androidx.lifecycle.LifecycleOwner;
import androidx.lifecycle.ViewModelProvider;

import static android.view.View.INVISIBLE;
import static android.view.View.VISIBLE;
import static org.briarproject.bramble.api.crypto.DecryptionResult.SUCCESS;


public class TimerPinFragment extends BaseFragment implements TextWatcher {

	final static String TAG = TimerPinFragment.class.getName();

	@Inject
	ViewModelProvider.Factory viewModelFactory;

	private TimerViewModel viewModel;
	private Button signInButton;

	private String userTimerString = "";
	private TextView userTimerInput;
	CountDownTimer timer;

	@Override
	public void injectFragment(ActivityComponent component) {
		component.inject(this);
		viewModel = new ViewModelProvider(requireActivity(), viewModelFactory)
				.get(TimerViewModel.class);
	}

	@Override
	public View onCreateView(LayoutInflater inflater,
			@Nullable ViewGroup container,
			@Nullable Bundle savedInstanceState) {
		View v = inflater.inflate(R.layout.fragment_timer, container,
				false);

		LifecycleOwner owner = getViewLifecycleOwner();
		viewModel.getPasswordValidated().observeEvent(owner, result -> {
			if (result != SUCCESS) onPasswordInvalid(result);
		});

		userTimerInput = v.findViewById(R.id.timerInputView);

		GridLayout grid = (GridLayout) v.findViewById(R.id.gridView);
		int childCount = grid.getChildCount();

		for (int i= 0; i < childCount; i++){
			Button btn = (Button) grid.getChildAt(i);
			btn.setOnClickListener(new View.OnClickListener(){
				@Override
				public void onClick(View view){
					if (timer != null){
						timer.cancel();
						timer = null;
						userTimerString = "";
					}
					if (userTimerString.length() > 5) {
						userTimerString = "";
					}
					userTimerString += ((Button)view).getText().toString();
					String str = userTimerString.replaceAll("..(?!$)", "$0:");
					userTimerInput.setText(str);
				}
			});
		}
		signInButton = v.findViewById(R.id.btn_sign_in);
		signInButton.setOnClickListener(view -> onSignInButtonClicked());

		return v;
	}

	@Override
	public void beforeTextChanged(CharSequence s, int start, int count,
			int after) {
	}

	@Override
	public void onTextChanged(CharSequence s, int start, int before,
			int count) {
//		if (count > 0) setError(input, null, false);
	}

	@Override
	public void afterTextChanged(Editable s) {
	}

	private void onSignInButtonClicked() {
		if(userTimerString.length() > 0) {
			viewModel.validatePassword(userTimerString);
			signInButton.setVisibility(INVISIBLE);
		}
	}



	private void onPasswordInvalid(DecryptionResult result) {

		//start a timer
		signInButton.setVisibility(VISIBLE);

		int timerCount = parseUserInputToTimer() * 1000;
		timer = new CountDownTimer(timerCount, 1000) {

			@Override
			public void onTick(long millisUntilFinished) {
				int remaining = (int) millisUntilFinished / 1000;
				int hours = remaining / 3600;
				int minutes = (remaining % 3600) / 60;
				int seconds = remaining % 60;

				String str  = String.format("%02d:%02d:%02d", hours, minutes, seconds);
				userTimerInput.setText(str);
			}

			@Override
			public void onFinish() {
				String remaining = "00:00:00";
				userTimerInput.setText(remaining);
				userTimerString = "";
			}

		};
		timer.start();

	}

	int parseUserInputToTimer(){
		int outputSeconds = 0;

		String[] parsedArray = splitStringEvery(userTimerString, 2);
		if(parsedArray.length == 1){
			//only seconds
			outputSeconds = Integer.parseInt(parsedArray[0]);
		} else if(parsedArray.length == 2){
			//first part is minutes, second is seconds
			int min = Integer.parseInt(parsedArray[0]);
			int sec = Integer.parseInt(parsedArray[1]);
			outputSeconds = (min*60) + sec;
		} else if(parsedArray.length == 3){
			//first part is hours, second is minutes, third is seconds
			int hours = Integer.parseInt(parsedArray[0]);
			int min = Integer.parseInt(parsedArray[1]);
			int sec = Integer.parseInt(parsedArray[2]);
			outputSeconds = (hours*3600)+(min*60)+sec;
		}

		return outputSeconds;
	}

	public String[] splitStringEvery(String s, int interval) {
		int arrayLength = (int) Math.ceil(((s.length() / (double)interval)));
		String[] result = new String[arrayLength];

		int j = 0;
		int lastIndex = result.length - 1;
		for (int i = 0; i < lastIndex; i++) {
			result[i] = s.substring(j, j + interval);
			j += interval;
		} //Add the last bit
		result[lastIndex] = s.substring(j);

		return result;
	}

	@Override
	public String getUniqueTag() {
		return TAG;
	}


}

