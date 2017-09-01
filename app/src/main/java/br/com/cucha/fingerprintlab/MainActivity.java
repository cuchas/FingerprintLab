package br.com.cucha.fingerprintlab;

import android.Manifest;
import android.annotation.SuppressLint;
import android.annotation.TargetApi;
import android.content.pm.PackageManager;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.v4.app.ActivityCompat;
import android.support.v4.app.NavUtils;
import android.support.v4.hardware.fingerprint.FingerprintManagerCompat;
import android.support.v4.hardware.fingerprint.FingerprintManagerCompat.AuthenticationCallback;
import android.support.v4.os.CancellationSignal;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Toast;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.Enumeration;

public class MainActivity extends AppCompatActivity implements View.OnClickListener {

    private static final int FINGERPRINT_PERMISSION_REQUEST = 1001;
    @SuppressLint("InlinedApi")
    static final String FINGERPRINT_PERMISSION = Manifest.permission.USE_FINGERPRINT;
    private static final String KEYSTORE_PROVIDER = "AndroidKeyStore";
    private static final String ALIAS = "somelias";
    private static final String TAG = MainActivity.class.getName();
    private FingerprintManagerCompat fpm;
    private AuthCallback authCallback = new AuthCallback();
    private CancellationSignal cancellationSignal = new CancellationSignal();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        fpm = FingerprintManagerCompat.from(this);

        findViewById(R.id.button).setOnClickListener(this);
    }

    @Override
    public void onClick(View view) {

        if (android.os.Build.VERSION.SDK_INT < android.os.Build.VERSION_CODES.M) {
            Toast.makeText(this, getString(R.string.unsupported_api), Toast.LENGTH_SHORT).show();
            return;
        }

        if (!fpm.isHardwareDetected()) {
            Toast.makeText(this, getString(R.string.no_fingerprint_hardware), Toast.LENGTH_SHORT)
                    .show();
            return;
        }

        int permission = ActivityCompat.checkSelfPermission(this, FINGERPRINT_PERMISSION);

        if (permission != PackageManager.PERMISSION_GRANTED) {

            String[] permissionList = new String[]{FINGERPRINT_PERMISSION};
            ActivityCompat.requestPermissions(this, permissionList, FINGERPRINT_PERMISSION_REQUEST);
            return;
        }

        readFingerprint();
    }

    private void readFingerprint() {
        if (!fpm.hasEnrolledFingerprints()) {
            Toast.makeText(this, getString(R.string.no_fingerprints_registered), Toast.LENGTH_SHORT)
                    .show();
            return;
        }

        Toast.makeText(this, getString(R.string.has_fingerprint), Toast.LENGTH_SHORT).show();

        listEntries();

//        final KeyPair keyPair = generatePrivateKey();

        final Signature signature = getSignature();

        final FingerprintManagerCompat.CryptoObject cryptoObject =
                new FingerprintManagerCompat.CryptoObject(signature);


        fpm.authenticate(cryptoObject, 0, cancellationSignal, authCallback, null);
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);

        if (requestCode == FINGERPRINT_PERMISSION_REQUEST) {

            for (int i = 0; i < permissions.length; i++) {

                if (permissions[i].equals(FINGERPRINT_PERMISSION)) {

                    if (grantResults[i] == PackageManager.PERMISSION_GRANTED)
                        readFingerprint();

                    return;
                }
            }
        }
    }

    @TargetApi(Build.VERSION_CODES.M)
    private KeyPair generatePrivateKey() {
        /*
         * Generate a new EC key pair entry in the Android Keystore by
         * using the KeyPairGenerator API. The private key can only be
         * used for signing or verification and only with SHA-256 or
                        * SHA-512 as the message digest.
         */
        final String keyAlgorithmEc = KeyProperties.KEY_ALGORITHM_EC;

        KeyPairGenerator kpg = null;
        try {
            kpg = KeyPairGenerator.getInstance(keyAlgorithmEc, KEYSTORE_PROVIDER);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
            return null;
        }

        try {

            final KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec.Builder(
                    ALIAS,
                    KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                    .setUserAuthenticationRequired(true)
                    .setUserAuthenticationValidityDurationSeconds(30)
                    .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                    .build();

            kpg.initialize(keyGenParameterSpec);

        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }

        KeyPair kp = kpg.generateKeyPair();

        return kp;
    }

    private void listEntries() {
        /*
         * Load the Android KeyStore instance using the the
         * "AndroidKeyStore" provider to list out what entries are
         * currently stored.
         */
        KeyStore ks = null;
        try {
            ks = KeyStore.getInstance(KEYSTORE_PROVIDER);
            ks.load(null);
            Enumeration<String> aliases = ks.aliases();

            while (aliases.hasMoreElements()) {
                Log.i(TAG, aliases.nextElement());
            }

        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private byte[] signData(byte[] data) {
        /*
         * Use a PrivateKey in the KeyStore to create a signature over
         * some data.
         */
        Signature s = getSignature();

        if (s == null) return null;

        try {
            s.update(data);
        } catch (SignatureException e) {
            e.printStackTrace();
        }

        try {
            byte[] sign = s.sign();

            return sign;

        } catch (SignatureException e) {
            e.printStackTrace();
        }

        return null;
    }

    @Nullable
    private Signature getSignature() {
        KeyStore ks = null;

        try {
            ks = KeyStore.getInstance("AndroidKeyStore");
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }

        try {
            ks.load(null);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        }

        KeyStore.Entry entry = null;

        try {
            entry = ks.getEntry(ALIAS, null);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnrecoverableEntryException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }

        if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
            Log.w(TAG, "Not an instance of a PrivateKeyEntry");
            return null;
        }

        Signature s = null;
        try {
            s = Signature.getInstance("SHA256withECDSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        try {
            s.initSign(((KeyStore.PrivateKeyEntry) entry).getPrivateKey());
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        return s;
    }

    private boolean verifyData(byte[] data) {
        /*
         * Verify a signature previously made by a PrivateKey in our
         * KeyStore. This uses the X.509 certificate attached to our
         * private key in the KeyStore to validate a previously
         * generated signature.
         */
        KeyStore ks = null;
        try {
            ks = KeyStore.getInstance(KEYSTORE_PROVIDER);
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }

        try {
            ks.load(null);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        }

        KeyStore.Entry entry = null;

        try {
            entry = ks.getEntry(ALIAS, null);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnrecoverableEntryException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }

        if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
            Log.w(TAG, "Not an instance of a PrivateKeyEntry");
            return false;
        }

        Signature s = null;

        try {
            s = Signature.getInstance("SHA256withECDSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        try {
            s.initVerify(((KeyStore.PrivateKeyEntry) entry).getCertificate());
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }

        try {
            s.update(data);
        } catch (SignatureException e) {
            e.printStackTrace();
        }

        boolean valid = false;
        try {
            valid = s.verify(data);
        } catch (SignatureException e) {
            e.printStackTrace();
        }

        return valid;
    }

    private class AuthCallback extends AuthenticationCallback {
        @Override
        public void onAuthenticationError(int errMsgId, CharSequence errString) {
            super.onAuthenticationError(errMsgId, errString);
        }

        @Override
        public void onAuthenticationSucceeded(FingerprintManagerCompat.AuthenticationResult result) {
            super.onAuthenticationSucceeded(result);
        }
    }
}
