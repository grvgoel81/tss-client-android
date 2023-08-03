package com.web3auth.tss_client_android.client;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SHA512 {
    public static byte[] digest(byte[] buf) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-512");
        digest.update(buf);
        return digest.digest();
    }
}
