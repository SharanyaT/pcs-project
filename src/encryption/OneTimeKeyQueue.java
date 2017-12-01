package encryption;

import org.whispersystems.curve25519.Curve25519KeyPair;

import java.security.KeyPair;
import java.util.ArrayDeque;

public class OneTimeKeyQueue extends ArrayDeque<KeyPair> {

    private static final int KEYS_TO_ADD = 5;

    @Override
    public KeyPair poll(){
        if (isEmpty()){
            for (int i = 0; i < KEYS_TO_ADD; i++){
                add(EncryptionHandler.generateKeyPair());
            }
        }
        return super.poll();
    }
}
