package me.smartproxy.ui;

import android.annotation.SuppressLint;
import android.app.AlertDialog;
import android.content.DialogInterface;
import android.content.DialogInterface.OnClickListener;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.SharedPreferences.Editor;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.text.InputType;
import android.text.TextUtils;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.CompoundButton;
import android.widget.CompoundButton.OnCheckedChangeListener;
import android.widget.EditText;
import android.widget.ScrollView;
import android.widget.Switch;
import android.widget.TextView;
import android.widget.Toast;

import com.google.zxing.integration.android.IntentIntegrator;
import com.google.zxing.integration.android.IntentResult;

import java.io.File;
import java.util.Calendar;

import me.smartproxy.R;
import me.smartproxy.core.LocalVpnService;
import me.smartproxy.core.ProxyConfig;
import me.smartproxy.util.DebugLog;

/**
 * Created by zengzheying on 15/12/23.
 */
public class MainActivity extends AppCompatActivity implements
		View.OnClickListener,
		OnCheckedChangeListener,
		LocalVpnService.onStatusChangedListener {

	private static final String TAG = MainActivity.class.getSimpleName();
	private static final String CONFIG_URL_KEY = "CONFIG_URL_KEY";
	private static final int START_VPN_SERVICE_REQUEST_CODE = 1985;
	private static String GL_HISTORY_LOGS;
	private Switch switchProxy;
	private TextView textViewLog;
	private ScrollView scrollViewLog;
	private TextView textViewConfigUrl;
	private Calendar mCalendar;

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.content_main);

		scrollViewLog = (ScrollView) findViewById(R.id.scrollViewLog);
		textViewLog = (TextView) findViewById(R.id.textViewLog);
		findViewById(R.id.configUrlLayout).setOnClickListener(this);

		textViewConfigUrl = (TextView) findViewById(R.id.textViewConfigUrl);
		String configUrl = readConfigUrl();
		if (TextUtils.isEmpty(configUrl)) {
			textViewConfigUrl.setText(R.string.config_not_set_value);
		} else {
			textViewConfigUrl.setText(configUrl);
		}

		textViewLog.setText(GL_HISTORY_LOGS);
		scrollViewLog.fullScroll(ScrollView.FOCUS_DOWN);

		mCalendar = Calendar.getInstance();
		LocalVpnService.addOnStatusChangedListener(this);
	}

	@Override
	protected void onDestroy() {
		LocalVpnService.removeOnStatusChangedListener(this);
		super.onDestroy();
	}

	String readConfigUrl() {
		SharedPreferences preferences = getSharedPreferences("SmartProxy", MODE_PRIVATE);
		return preferences.getString(CONFIG_URL_KEY, "");
	}

	void setConfigUrl(String configUrl) {
		SharedPreferences preferences = getSharedPreferences("SmartProxy", MODE_PRIVATE);
		Editor editor = preferences.edit();
		editor.putString(CONFIG_URL_KEY, configUrl);
		editor.apply();
	}

	String getVersionName() {
		PackageManager packageManager = getPackageManager();
		if (packageManager == null) {
			if (ProxyConfig.IS_DEBUG) {
				DebugLog.e("null package manager is impossible");
			}
			return null;
		}

		try {
			return packageManager.getPackageInfo(getPackageName(), 0).versionName;
		} catch (PackageManager.NameNotFoundException e) {
			if (ProxyConfig.IS_DEBUG) {
				DebugLog.e("package not found is impossible %s", e);
			}
			return null;
		}
	}

	boolean isValidUrl(String url) {
		try {
			if (url == null || url.isEmpty())
				return false;

			if (url.startsWith("/")) {//file path
				File file = new File(url);
				if (!file.exists()) {
					onLogReceived(String.format("File(%s) not exists.", url));
					return false;
				}
				if (!file.canRead()) {
					onLogReceived(String.format("File(%s) can't read.", url));
					return false;
				}
			} else { //url
				Uri uri = Uri.parse(url);
				if (!"http".equals(uri.getScheme()) && !"https".equals(uri.getScheme()))
					return false;
				if (uri.getHost() == null)
					return false;
			}
			return true;
		} catch (Exception e) {
			return false;
		}
	}

	@Override
	public void onClick(View v) {
		if (switchProxy.isChecked()) {
			return;
		}

		new AlertDialog.Builder(this)
				.setTitle(R.string.config_url)
				.setItems(new CharSequence[]{
						getString(R.string.config_url_scan),
						getString(R.string.config_url_manual)
				}, new OnClickListener() {
					@Override
					public void onClick(DialogInterface dialogInterface, int i) {
						switch (i) {
							case 0:
								scanForConfigUrl();
								break;
							case 1:
								showConfigUrlInputDialog();
								break;
						}
					}
				})
				.show();
	}

	private void scanForConfigUrl() {
		new IntentIntegrator(this)
				.setResultDisplayDuration(0)
				.setPrompt(getString(R.string.config_url_scan_hint))
				.initiateScan(IntentIntegrator.QR_CODE_TYPES);
	}

	private void showConfigUrlInputDialog() {
		final EditText editText = new EditText(this);
		editText.setInputType(InputType.TYPE_TEXT_VARIATION_URI);
		editText.setHint(getString(R.string.config_url_hint));
		editText.setText(readConfigUrl());

		new AlertDialog.Builder(this)
				.setTitle(R.string.config_url)
				.setView(editText)
				.setPositiveButton(R.string.btn_ok, new OnClickListener() {
					@Override
					public void onClick(DialogInterface dialog, int which) {
						if (editText.getText() == null) {
							return;
						}

						String configUrl = editText.getText().toString().trim();
						if (isValidUrl(configUrl)) {
							setConfigUrl(configUrl);
							textViewConfigUrl.setText(configUrl);
						} else {
							Toast.makeText(MainActivity.this, R.string.err_invalid_url, Toast.LENGTH_SHORT).show();
						}
					}
				})
				.setNegativeButton(R.string.btn_cancel, null)
				.show();
	}

	@Override
	public void onStatusChanged(String status, Boolean isRunning) {
		switchProxy.setEnabled(true);
		switchProxy.setChecked(isRunning);
		onLogReceived(status);
		Toast.makeText(this, status, Toast.LENGTH_SHORT).show();
	}

	@SuppressLint("DefaultLocale")
	@Override
	public void onLogReceived(String logString) {
		mCalendar.setTimeInMillis(System.currentTimeMillis());
		logString = String.format("[%1$02d:%2$02d:%3$02d] %4$s\n",
				mCalendar.get(Calendar.HOUR_OF_DAY),
				mCalendar.get(Calendar.MINUTE),
				mCalendar.get(Calendar.SECOND),
				logString);

		System.out.println(logString);

		if (textViewLog.getLineCount() > 200) {
			textViewLog.setText("");
		}
		textViewLog.append(logString);
		scrollViewLog.fullScroll(ScrollView.FOCUS_DOWN);
		GL_HISTORY_LOGS = textViewLog.getText() == null ? "" : textViewLog.getText().toString();
	}

	@Override
	public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
		if (LocalVpnService.IsRunning != isChecked) {
			switchProxy.setEnabled(false);
			if (isChecked) {
				Intent intent = LocalVpnService.prepare(this);
				if (intent == null) {
					startVPNService();
				} else {
					startActivityForResult(intent, START_VPN_SERVICE_REQUEST_CODE);
				}
			} else {
				LocalVpnService.IsRunning = false;
			}
		}
	}

	private void startVPNService() {
		String configUrl = readConfigUrl();
		if (!isValidUrl(configUrl)) {
			Toast.makeText(this, R.string.err_invalid_url, Toast.LENGTH_SHORT).show();
			switchProxy.post(new Runnable() {
				@Override
				public void run() {
					switchProxy.setChecked(false);
					switchProxy.setEnabled(true);
				}
			});
			return;
		}

		textViewLog.setText("");
		GL_HISTORY_LOGS = null;
		onLogReceived("starting...");
		LocalVpnService.ConfigUrl = configUrl;
		startService(new Intent(this, LocalVpnService.class));
	}

	@Override
	protected void onActivityResult(int requestCode, int resultCode, Intent intent) {
		if (requestCode == START_VPN_SERVICE_REQUEST_CODE) {
			if (resultCode == RESULT_OK) {
				startVPNService();
			} else {
				switchProxy.setChecked(false);
				switchProxy.setEnabled(true);
				onLogReceived("canceled.");
			}
			return;
		}

		IntentResult scanResult = IntentIntegrator.parseActivityResult(requestCode, resultCode, intent);
		if (scanResult != null) {
			String configUrl = scanResult.getContents();
			if (isValidUrl(configUrl)) {
				setConfigUrl(configUrl);
				textViewConfigUrl.setText(configUrl);
			} else {
				Toast.makeText(MainActivity.this, R.string.err_invalid_url, Toast.LENGTH_SHORT).show();
			}
			return;
		}

		super.onActivityResult(requestCode, resultCode, intent);
	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		getMenuInflater().inflate(R.menu.main_activity_actions, menu);

		MenuItem menuItem = menu.findItem(R.id.menu_item_switch);
		if (menuItem == null) {
			return false;
		}

		switchProxy = (Switch) menuItem.getActionView();
		if (switchProxy == null) {
			return false;
		}

		switchProxy.setChecked(LocalVpnService.IsRunning);
		switchProxy.setOnCheckedChangeListener(this);

		return true;
	}

	@Override
	public boolean onOptionsItemSelected(MenuItem item) {
		switch (item.getItemId()) {
			case R.id.menu_item_about:
				new AlertDialog.Builder(this)
						.setTitle(getString(R.string.app_name) + getVersionName())
						.setMessage(R.string.about_info)
						.setPositiveButton(R.string.btn_ok, null)
						.setNegativeButton(R.string.btn_more, new OnClickListener() {
							@Override
							public void onClick(DialogInterface dialog, int which) {
								startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse("http://smartproxy.me")));
							}
						})
						.show();

				return true;
			case R.id.menu_item_exit:
				if (!LocalVpnService.IsRunning) {
					finish();
					return true;
				}

				new AlertDialog.Builder(this)
						.setTitle(R.string.menu_item_exit)
						.setMessage(R.string.exit_confirm_info)
						.setPositiveButton(R.string.btn_ok, new OnClickListener() {
							@Override
							public void onClick(DialogInterface dialog, int which) {
								LocalVpnService.IsRunning = false;
								LocalVpnService.Instance.disconnectVPN();
								stopService(new Intent(MainActivity.this, LocalVpnService.class));
								System.runFinalization();
								System.exit(0);
							}
						})
						.setNegativeButton(R.string.btn_cancel, null)
						.show();

				return true;
			default:
				return super.onOptionsItemSelected(item);
		}
	}

}
