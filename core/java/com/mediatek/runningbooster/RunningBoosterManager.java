package com.mediatek.runningbooster;

import android.content.Context;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.util.Slog;
import com.mediatek.runningbooster.RbConfiguration;
import com.mediatek.runningbooster.IRunningBoosterManager;
import java.util.List;

/**
 * Provide the  interface for the APK which allow to use RunningBoosterService.
 */
public class RunningBoosterManager {

    private final String TAG = "RunningBoosterManager";
    private Context mContext;
    private IRunningBoosterManager mRunningBoosterService;

    public RunningBoosterManager(Context context) {
        mContext = context;

        if (null == mRunningBoosterService) {
            mRunningBoosterService = IRunningBoosterManager.Stub.asInterface
                    (ServiceManager.getService("running_booster"));
            Slog.d(TAG, "Get RunningBoosterService");
        }
    }

    /**
    * Used by App which allows to use RunningBoosterService,
    * App may set specific configuration by this API.
    */
   public void applyUserConfig(String packageName, RbConfiguration config)
            throws SecurityException {
        Slog.d(TAG, "applyUserConfig packageName=" + packageName + " config="+config);

        try {
            if(null != mRunningBoosterService) {
                mRunningBoosterService.applyUserConfig(packageName, config);
            }
        } catch (RemoteException e) {
            Slog.d(TAG, "applyUserConfig packageName RemoteException");
            e.printStackTrace();
        }
    }

    /**
    * Provide the API version of RunningBoosterService.
    * @return API version of RunningBoosterService.
    */
    public String getAPIVersion() throws SecurityException {
        Slog.d(TAG, "[RunningBoosterManager] getAPIVersion");
        try {
            if(null != mRunningBoosterService) {
                return mRunningBoosterService.getAPIVersion();
            }
        } catch (RemoteException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
    * Provide the white list which the platform configured.
    * @return The white list which the platform configured.
    */
    public List<String> getPlatformWhiteList() throws SecurityException {
        Slog.d(TAG, "[RunningBoosterManager] getPlatformWhiteList");
        try {
            if(null != mRunningBoosterService) {
                return mRunningBoosterService.getPlatformWhiteList();
            }
        } catch (RemoteException e) {
            e.printStackTrace();
        }
        return null;
    }
}