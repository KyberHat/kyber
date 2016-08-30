package org.briarproject.api.introduction;

import static org.briarproject.api.introduction.IntroductionConstants.TYPE_ABORT;
import static org.briarproject.api.introduction.IntroductionConstants.TYPE_ACK;
import static org.briarproject.api.introduction.IntroductionConstants.TYPE_REQUEST;
import static org.briarproject.api.introduction.IntroductionConstants.TYPE_RESPONSE;

public enum IntroduceeAction {

	LOCAL_ACCEPT,
	LOCAL_DECLINE,
	LOCAL_ABORT,
	REMOTE_REQUEST,
	REMOTE_ACCEPT,
	REMOTE_DECLINE,
	REMOTE_ABORT,
	ACK;

	public static IntroduceeAction getRemote(int type, boolean accept) {
		if (type == TYPE_REQUEST) return REMOTE_REQUEST;
		if (type == TYPE_RESPONSE && accept) return REMOTE_ACCEPT;
		if (type == TYPE_RESPONSE) return REMOTE_DECLINE;
		if (type == TYPE_ACK) return ACK;
		if (type == TYPE_ABORT) return REMOTE_ABORT;
		return null;
	}

	public static IntroduceeAction getRemote(int type) {
		return getRemote(type, true);
	}

	public static IntroduceeAction getLocal(int type, boolean accept) {
		if (type == TYPE_RESPONSE && accept) return LOCAL_ACCEPT;
		if (type == TYPE_RESPONSE) return LOCAL_DECLINE;
		if (type == TYPE_ACK) return ACK;
		if (type == TYPE_ABORT) return LOCAL_ABORT;
		return null;
	}

	public static IntroduceeAction getLocal(int type) {
		return getLocal(type, true);
	}

}
