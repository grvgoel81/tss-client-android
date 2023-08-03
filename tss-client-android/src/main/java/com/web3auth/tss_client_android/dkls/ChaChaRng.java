package com.web3auth.tss_client_android.dkls;

import android.os.Build;

import androidx.annotation.RequiresApi;

import com.web3auth.tss_client_android.client.SECP256K1;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public final class ChaChaRng {
    private final long pointer;

    @RequiresApi(api = Build.VERSION_CODES.O)
    public ChaChaRng() throws DKLSError {
        DKLSError dklsError = new DKLSError();
        byte[] stateBytes = SECP256K1.generatePrivateKey();
        if (stateBytes == null) {
            throw new DKLSError("Error generating random bytes for generator initialization");
        }
        // convert bytes to base64
        String state = Base64.getEncoder().encodeToString(stateBytes);
        byte[] base64Bytes = state.getBytes(StandardCharsets.UTF_8);
        long ptr = jniChaChaRng(state, dklsError);
        if (dklsError.code != 0) {
            throw dklsError;
        }
        pointer = ptr;
    }

    private native long jniChaChaRng(String state, DKLSError error);

    private native void jniChaChaRngFree();

    @Override
    protected void finalize() throws Throwable {
        super.finalize();
        jniChaChaRngFree();
    }

    public long getPointer() {
        return pointer;
    }
}
