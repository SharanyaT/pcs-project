package encryption;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;

// https://gist.github.com/zcdziura/7652286
/*

Create /lib folder and add most recent BouncyCastle jar from http://www.bouncycastle.org/latest_releases.html
Make sure your IDE is configured to use the /lib folder. Don't try to automatically get it through Maven because
it wasn't signed there for some reason and Java will refuse to run unsigned crypto libraries.

Download JCE from http://www.oracle.com/technetwork/java/javase/downloads/jce-7-download-432124.html and put the two
.jar files in $JAVA_HOME/jre/lib/security (overwrite the ones already there) because Java will refuse to run anything
more than most basic crypto out of the box because it's apparently illegal in some countries.

Basically Java will refuse to run your code because it hates you.

 */



public class EncryptionHandler {
    private static byte[] iv = new SecureRandom().generateSeed(16);

    public static KeyPair generateECKeys() {
        try {
            ECNamedCurveParameterSpec parameterSpec = ECNamedCurveTable.getParameterSpec("brainpoolp256r1");
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                    "ECDH", "BC");

            keyPairGenerator.initialize(parameterSpec);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            return keyPair;
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static SecretKey generateSharedSecret(PrivateKey privateKey,
                                                 PublicKey publicKey) {
        try {
            KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", "BC");
            keyAgreement.init(privateKey);
            keyAgreement.doPhase(publicKey, true);

            SecretKey key = keyAgreement.generateSecret("AES");
            return key;
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String encryptString(SecretKey key, String plainText) {
        try {
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
            byte[] plainTextBytes = plainText.getBytes("UTF-8");
            byte[] cipherText;

            cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
            cipherText = new byte[cipher.getOutputSize(plainTextBytes.length)];
            int encryptLength = cipher.update(plainTextBytes, 0,
                    plainTextBytes.length, cipherText, 0);
            encryptLength += cipher.doFinal(cipherText, encryptLength);

            return bytesToHex(cipherText);
        } catch (GeneralSecurityException | UnsupportedEncodingException  e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String decryptString(SecretKey key, String cipherText) {
        try {
            Key decryptionKey = new SecretKeySpec(key.getEncoded(),
                    key.getAlgorithm());
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
            byte[] cipherTextBytes = hexToBytes(cipherText);
            byte[] plainText;

            cipher.init(Cipher.DECRYPT_MODE, decryptionKey, ivSpec);
            plainText = new byte[cipher.getOutputSize(cipherTextBytes.length)];
            int decryptLength = cipher.update(cipherTextBytes, 0,
                    cipherTextBytes.length, plainText, 0);
            decryptLength += cipher.doFinal(plainText, decryptLength);

            return new String(plainText, "UTF-8");
        } catch (GeneralSecurityException | UnsupportedEncodingException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static PublicKey publicKeyFromString(String stored)  {
        byte[] keyBytes = Base64.decodeBase64(stored);
        PublicKey pub = null;
        try{
            KeyFactory keyFactory = KeyFactory.getInstance("ECDH", "BC");
            pub = keyFactory.generatePublic(new X509EncodedKeySpec(keyBytes));
        } catch (GeneralSecurityException e){
            e.printStackTrace();
        }
        return pub;
    }

    public static String publicKeyToString(PublicKey publ) {
        return Base64.encodeBase64String(publ.getEncoded());
    }


    private static String bytesToHex(byte[] data, int length) {
        String digits = "0123456789ABCDEF";
        StringBuffer buffer = new StringBuffer();

        for (int i = 0; i != length; i++) {
            int v = data[i] & 0xff;

            buffer.append(digits.charAt(v >> 4));
            buffer.append(digits.charAt(v & 0xf));
        }

        return buffer.toString();
    }

    private static String bytesToHex(byte[] data) {
        return bytesToHex(data, data.length);
    }

    private static byte[] hexToBytes(String string) {
        int length = string.length();
        byte[] data = new byte[length / 2];
        for (int i = 0; i < length; i += 2) {
            data[i / 2] = (byte) ((Character.digit(string.charAt(i), 16) << 4) + Character
                    .digit(string.charAt(i + 1), 16));
        }
        return data;
    }

}