package encryption;

import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Security;
import java.util.Arrays;

import static encryption.EncryptionHandler.*;

public class TestEncryptionHandler {

    public static void main(String[] args) throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        testEncryptDecrypt();
        testEncodeKeys();
    }

    private static void testEncryptDecrypt(){
        String plainText = "Look mah, I'm a message!";
        System.out.println("Original plaintext message: " + plainText);

        // Initialize two key pairs
        KeyPair keyPairA = generateECKeys();
        KeyPair keyPairB = generateECKeys();

        // Create two AES secret keys to encrypt/decrypt the message
        SecretKey secretKeyA = generateSharedSecret(keyPairA.getPrivate(),
                keyPairB.getPublic());
        SecretKey secretKeyB = generateSharedSecret(keyPairB.getPrivate(),
                keyPairA.getPublic());

        // Encrypt the message using 'secretKeyA'
        String cipherText = encryptString(secretKeyA, plainText);
        System.out.println("Encrypted cipher text: " + cipherText);

        // Decrypt the message using 'secretKeyB'
        String decryptedPlainText = decryptString(secretKeyB, cipherText);
        System.out.println("Decrypted cipher text: " + decryptedPlainText);
        assert plainText.equals(decryptedPlainText);
    }

    private static void testEncodeKeys() throws GeneralSecurityException {

        // Initialize two key pairs
        KeyPair keyPairA = generateECKeys();
        PublicKey pubA = keyPairA.getPublic();
        System.out.println(pubA);
//        String publicStringA = publicKeyToString(pubA);
        String publicStringA = publicKeyToString(pubA);
        System.out.println("Key A: " + publicStringA);
        PublicKey newPubA = publicKeyFromString(publicStringA);
        System.out.println("New key :" +  newPubA);
        assert Arrays.equals(pubA.getEncoded(), newPubA.getEncoded());
    }
}
