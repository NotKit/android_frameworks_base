/*
* Copyright (C) 2014 MediaTek Inc.
* Modification based on code covered by the mentioned copyright
* and/or permission notice(s).
*/
/*
 * Copyright (C) 2006 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.server;
				
import android.database.ContentObserver;
import android.os.BatteryStats;

import android.os.ResultReceiver;
import android.os.ShellCommand;
import com.android.internal.app.IBatteryStats;
import com.android.server.am.BatteryStatsService;
import com.android.server.lights.Light;
import com.android.server.lights.LightsManager;

import android.app.ActivityManagerNative;
import android.content.ContentResolver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.content.BroadcastReceiver;
import android.os.BatteryManager;
import android.os.BatteryManagerInternal;
import android.os.BatteryProperties;
import android.os.Binder;
import android.os.FileUtils;
import android.os.Handler;
import android.os.IBatteryPropertiesListener;
import android.os.IBatteryPropertiesRegistrar;
import android.os.IBinder;
import android.os.DropBoxManager;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.os.SystemClock;
import android.os.UEventObserver;
import android.os.SystemProperties;
import android.os.UserHandle;
import android.provider.Settings;
import android.util.EventLog;
import android.util.Log;
import android.util.Slog;

import java.io.File;
import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import android.hardware.ILedManager;
import android.app.Service;
import java.io.FileWriter;
import java.util.Timer;
import java.util.TimerTask;

public final class LedService extends SystemService{
    private static final String TAG = LedService.class.getSimpleName();

		private Context mContext;
		private Timer mTimer = null;
		private LedTask mLedTask =null;
		private int temId = 0;
    public LedService(Context context) {
        super(context); //guohuajun removed

        mContext = context;
       
    }

	private final ILedManager.Stub mLBinderService = new ILedManager.Stub() {
		@Override
		public boolean openLed(int id,int r,int g,int b){
			android.util.Log.d("hzh_led","openLed LightsManager.LIGHT_ID_LED : "+LightsManager.LIGHT_ID_LED);
			/*Light l =getLocalService(LightsManager.class).getLight(LightsManager.LIGHT_ID_LED);
			l.setLedColor(id,r,g,b);*/
			setLed(id,r,g,b);
			return true;
		}
	
		public boolean setRollingLed(int R,int G,int B,int time){
			return rollingLed(R,G,B,time);
		}
		public void cancelLedRolling(){
			cancelRolling();
		}
		public boolean switchHeaders(int id){
			return setHeaders(id);
		}
	};
	
	class LedTask extends TimerTask{
		int r;
		int g;
		int b;
		public LedTask(int r,int g,int b){
			this.r = r;
			this.g = g;
			this.b = b;
		}
		@Override
		public void run() {
			if(temId >5){
				temId =0;
			}
			for(int i=0;i<=5;i++){
				setLed(i,r,g,b);
			}
			setLed(temId,r,g,b);
			temId++;
			
		}
	}
	
	public boolean rollingLed(int R,int G,int B,int time){
		mTimer = new Timer();
		mLedTask = new LedTask(R,G,B);
		mTimer.schedule(mLedTask,0,time);
		return true;
		
	}
	public void cancelRolling(){
		if(mTimer !=null){
			mTimer.cancel();
			mTimer =null;
		}
		if(mLedTask != null){
			mLedTask =null;
		}
		
	}
	public boolean setLed(int ledId,int R,int G,int B){
		if(ledId >7||R>3||G>3||B>3){
			Log.d(TAG,"Exception : 参数错误");
			return false;
		}
		File file = new File("/proc/aw9120_operation");
		if(!file.exists()){
			Log.d(TAG,"Exception : 文件不存在");
			return false;
		}
		//FileOutputStream foStream =new FileOutputStream(file);
		String outString = ledId+" "+R+" "+G+" "+B;
		FileWriter fw = null;
		try {
			fw = new FileWriter(file);
			fw.write(outString);
		} catch (IOException e) {
			Log.d(TAG,"IOException : "+e);
			e.printStackTrace();
			return false;
		}finally{
			if(fw!=null){
				try {
					fw.close();
				} catch (IOException e) {
					Log.d(TAG,"IOException : "+e);
					e.printStackTrace();
					return false;
				}
			}
			
		}
		FileOutputStream fRed;
		FileOutputStream fGreen;
		try {
			fRed= new FileOutputStream("/sys/class/leds/red/brightness");
			fGreen= new FileOutputStream("/sys/class/leds/green/brightness");
			byte[] LIGHT_ON =  { '2', '5', '5' };
			byte[] LIGHT_OFF = { '0' };
			if(ledId == 5 && R > 0){
				fRed.write(LIGHT_ON);
				fGreen.write(LIGHT_OFF);
			} else if(ledId == 5 && G > 0){
				fRed.write(LIGHT_OFF);
				fGreen.write(LIGHT_ON);
			} else if(ledId == 5){
				fRed.write(LIGHT_OFF);
				fGreen.write(LIGHT_OFF);
			}
			if(fRed != null) fRed.close();
			if(fGreen != null) fGreen.close();
		} catch (IOException e) {
			Log.d(TAG,"Led IOException : "+e);
			e.printStackTrace();
		}
		return true;
	}
	public boolean setHeaders(int id){
		File file = new File("/proc/headphone_cs");
		if(!file.exists()){
			Log.d(TAG,"Exception : 文件不存在");
			return false;
		}
		//FileOutputStream foStream =new FileOutputStream(file);
		String outString = ""+id;
		FileWriter fw = null;
		try {
			fw = new FileWriter(file);
			fw.write(outString);
		} catch (IOException e) {
			Log.d(TAG,"IOException : "+e);
			e.printStackTrace();
			return false;
		}finally{
			if(fw!=null){
				try {
					fw.close();
				} catch (IOException e) {
					Log.d(TAG,"IOException : "+e);
					e.printStackTrace();
					return false;
				}
			}
			
		}
		return true;
	}

	
  @Override
  public void onStart() {

      publishBinderService("custom_led", mLBinderService);
      //publishLocalService(BatteryManagerInternal.class, new LocalService());
  }


}
