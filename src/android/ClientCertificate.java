
package org.apache.cordova.clientcertificate;

import android.annotation.TargetApi;
import android.os.Build;
import org.apache.cordova.*;
import org.json.JSONArray;
import org.json.JSONException;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Enumeration;

@TargetApi(Build.VERSION_CODES.LOLLIPOP)
public class ClientCertificate extends CordovaPlugin {

    private String p12path = "";
    private String p12password = "";

    @Override
    public Boolean shouldAllowBridgeAccess(String url) {
        return super.shouldAllowBridgeAccess(url);
    }
    @Override
    public void initialize(CordovaInterface cordova, CordovaWebView webView) {
        super.initialize(cordova, webView);

    }

    @TargetApi(Build.VERSION_CODES.LOLLIPOP)
    @Override
    public boolean onReceivedClientCertRequest(CordovaWebView view, ICordovaClientCertRequest request) {
        try {
            KeyStore keystore = KeyStore.getInstance("PKCS12");

            InputStream astream = cordova.getActivity().getApplicationContext().getAssets().open(p12path);
            keystore.load(astream, p12password.toCharArray());
            astream.close();
            Enumeration e = keystore.aliases();
            if (e.hasMoreElements()) {
                String ealias = (String) e.nextElement();
                PrivateKey key = (PrivateKey) keystore.getKey(ealias, p12password.toCharArray());
                java.security.cert.Certificate[]  chain = keystore.getCertificateChain(ealias);
                X509Certificate[] certs = Arrays.copyOf(chain, chain.length, X509Certificate[].class);
                request.proceed(key,certs);
            } else
            {
                request.ignore();
            }

        } catch (Exception ex)
        {
            request.ignore();
        }
        return true;
    }

    @Override
    public boolean execute(String action, JSONArray a, CallbackContext c) throws JSONException {
        if (action.equals("register"))
        {
            p12path = "www/" + a.getString(0);
            p12password = a.getString(1);
            c.success();
            return true;
        }
        c.error("Certificate path and password could not been set");
        return false;
    }


}
