package me.smartproxy.util;

import android.util.Log;

/**
 * Created by zengzheying on 15/12/25.
 */
public class DebugLog {

	private static final String TAG = "SmartProxy";

	public static void v(String format, Object... objs) {
		Log.v(TAG, format(format, objs));
	}

	public static void i(String format, Object... objs) {
		Log.i(TAG, format(format, objs));
	}

	public static void d(String format, Object... objs) {
		Log.d(TAG, format(format, objs));
	}

	public static void w(String format, Object... objs) {
		Log.w(TAG, format(format, objs));
	}

	public static void e(String format, Object... objs) {
		Log.e(TAG, format(format, objs));
	}

	private static String format(String format, Object... objs) {
		return String.format(format, objs);
	}
}
