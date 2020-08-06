package com.bomayric_android;

import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;
import androidx.appcompat.app.AppCompatActivity;
import androidx.biometric.BiometricPrompt;
import androidx.core.content.ContextCompat;

import android.os.Build;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.widget.Button;

import androidx.biometric.BiometricManager;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;


@RequiresApi(api = Build.VERSION_CODES.P)
public class MainActivity extends AppCompatActivity {
    private static final String KEY_NAME = "KeyName";
    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";
    private static final String FORWARD_SLASH = "/";
    private Button touchButton;

    @RequiresApi(api = Build.VERSION_CODES.P)
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        touchButton = findViewById(R.id.touch_button);
        touchButton.setOnClickListener((view) -> onTouchIdClick());
        displayBiometricButton();
    }

    private void onTouchIdClick() {
        getBiometricPromptHandler().authenticate(getBiometricPrompt(), new BiometricPrompt.CryptoObject(getCipher()));
        // Please see the below mentioned note section.
        // getBiometricPromptHandler().authenticate(getBiometricPrompt());
    }

    private boolean isBiometricCompatibleDevice() {
        if (getBiometricManager().canAuthenticate() == BiometricManager.BIOMETRIC_SUCCESS) {
            return true;
        } else {
            return false;
        }
    }

    private void displayBiometricButton() {
        if (isBiometricCompatibleDevice()) {
            touchButton.setEnabled(false);
        } else {
            touchButton.setEnabled(true);
            generateSecretKey();
        }
    }

    private BiometricManager getBiometricManager() {
        return BiometricManager.from(this);
    }

    private void generateSecretKey() {
        KeyGenerator keyGenerator = null;
        KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec.Builder(
                KEY_NAME, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                .setUserAuthenticationRequired(true)
                .setInvalidatedByBiometricEnrollment(false)
                .build();
        try {
            keyGenerator = KeyGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE);
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            e.printStackTrace();
        }
        if (keyGenerator != null) {
            try {
                keyGenerator.init(keyGenParameterSpec);
            } catch (InvalidAlgorithmParameterException e) {
                e.printStackTrace();
            }
            keyGenerator.generateKey();
        }
    }

    private SecretKey getSecretKey() {
        KeyStore keyStore = null;
        Key secretKey = null;
        try {
            keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        if (keyStore != null) {
            try {
                keyStore.load(null);
            } catch (CertificateException | IOException | NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
            try {
                secretKey = keyStore.getKey(KEY_NAME, null);
            } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
                e.printStackTrace();
            }
        }
        return (SecretKey) secretKey;
    }

    private Cipher getCipher() {
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + FORWARD_SLASH
                    + KeyProperties.BLOCK_MODE_CBC + FORWARD_SLASH
                    + KeyProperties.ENCRYPTION_PADDING_PKCS7);
            try {
                cipher.init(Cipher.ENCRYPT_MODE, getSecretKey());
            } catch (InvalidKeyException e) {
                e.printStackTrace();
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            e.printStackTrace();
        }
        return cipher;
    }

    private BiometricPrompt.PromptInfo getBiometricPrompt() {
        return new BiometricPrompt.PromptInfo.Builder()
                .setTitle("Biometric login for my app")
                .setSubtitle("Login with your biometric credential")
                .setNegativeButtonText("cancel")
                .setConfirmationRequired(false)
                .build();
    }

    private void onBiometricSuccess() {
        //Call the respective API on biometric success
//        callLoginApi("userName", "password");
    }

    private BiometricPrompt getBiometricPromptHandler() {
        return new BiometricPrompt(this, ContextCompat.getMainExecutor(this),
                new BiometricPrompt.AuthenticationCallback() {

                    @Override
                    public void onAuthenticationError(int errorCode, @NonNull CharSequence errString) {
                        super.onAuthenticationError(errorCode, errString);
                    }

                    @Override
                    public void onAuthenticationSucceeded(@NonNull BiometricPrompt.AuthenticationResult result) {
                        super.onAuthenticationSucceeded(result);
                        onBiometricSuccess();
                    }

                    @Override
                    public void onAuthenticationFailed() {
                        super.onAuthenticationFailed();
                    }
                }
        );
    }
}