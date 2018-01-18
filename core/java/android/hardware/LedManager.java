package android.hardware;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;

import android.util.Log;
import android.os.ServiceManager;
import android.os.IBinder;
//guohuajun add
import android.content.Context;

public class LedManager {
	
	private static  final String TAG = "LedManager";
	
	
	final ILedManager mService;  
  final Context mContext;  
    
  public LedManager(Context context, ILedManager service) {  
      mContext = context;  
      mService = service;  
  }  
  //guohuajun add  
  public Boolean openLed(int ledId,int R,int G,int B) {
  	
  		try{
						mService.openLed(ledId,R,G,B);
			} catch (Exception e) {
						Log.d(TAG,"run : error");
			}
			Log.d(TAG,"run : end");
			return true;
  }
  
 static public Boolean ledControl(int ledId,int R,int G,int B) {
		try{
		IBinder iB = ServiceManager.getService("custom_led");
		ILedManager mLedManager =  ILedManager.Stub.asInterface(iB);
		mLedManager.openLed(ledId,R,G,B);
		} catch (Exception e) {
			Log.d(TAG,"run : error");
				return false;
		}
		Log.d(TAG,"run : end");
		return true;
	}

	static public Boolean rollingLed(int R,int G,int B,int time) {
		try{
		IBinder iB = ServiceManager.getService("custom_led");
		ILedManager mLedManager =  ILedManager.Stub.asInterface(iB);
		mLedManager.setRollingLed(R,G,B,time);
		} catch (Exception e) {
			Log.d(TAG,"run : error");
		}
		Log.d(TAG,"run : end");
		return true;
	}
	
	static public Boolean cancelRolling() {
		try{
		IBinder iB = ServiceManager.getService("custom_led");
		ILedManager mLedManager =  ILedManager.Stub.asInterface(iB);
		mLedManager.cancelLedRolling();
		} catch (Exception e) {
			Log.d(TAG,"run : error");
		}
		Log.d(TAG,"run : end");
		return true;
	}
	
	
	static public Boolean setHeaders(int id) {
		try{
		IBinder iB = ServiceManager.getService("custom_led");
		ILedManager mLedManager =  ILedManager.Stub.asInterface(iB);
		mLedManager.switchHeaders(id);
		} catch (Exception e) {
			Log.d(TAG,"run : error");
		}
		Log.d(TAG,"run : end");
		return true;
	}
	
}
