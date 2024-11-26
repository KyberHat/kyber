package org.briarproject.briar.android.timer;


import org.briarproject.briar.android.viewmodel.ViewModelKey;

import androidx.lifecycle.ViewModel;
import dagger.Binds;
import dagger.Module;
import dagger.multibindings.IntoMap;

@Module
public abstract class TimerPinModule {

	@Binds
	@IntoMap
	@ViewModelKey(TimerViewModel.class)
	abstract ViewModel bindTimerViewModel(TimerViewModel viewModel);

	@Binds
	@IntoMap
	@ViewModelKey(ChangeTimerPinViewModel.class)
	abstract ViewModel bindChangeTimerPinViewModel(
			ChangeTimerPinViewModel viewModel);
}

