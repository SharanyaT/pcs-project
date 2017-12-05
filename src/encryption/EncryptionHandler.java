package encryption;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

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
    public static byte[] iv = new SecureRandom().generateSeed(16);

    public static void main(String[] args) {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
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
    }

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

    public static String bytesToHex(byte[] data, int length) {
        String digits = "0123456789ABCDEF";
        StringBuffer buffer = new StringBuffer();

        for (int i = 0; i != length; i++) {
            int v = data[i] & 0xff;

            buffer.append(digits.charAt(v >> 4));
            buffer.append(digits.charAt(v & 0xf));
        }

        return buffer.toString();
    }

    public static String bytesToHex(byte[] data) {
        return bytesToHex(data, data.length);
    }

    public static byte[] hexToBytes(String string) {
        int length = string.length();
        byte[] data = new byte[length / 2];
        for (int i = 0; i < length; i += 2) {
            data[i / 2] = (byte) ((Character.digit(string.charAt(i), 16) << 4) + Character
                    .digit(string.charAt(i + 1), 16));
        }
        return data;
    }

    public static PrivateKey privateKeyFromString(String key64) {
        byte[] clear = Base64.decode(key64);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(clear);
        KeyFactory fact;
        PrivateKey priv;
        try {
            fact = KeyFactory.getInstance("DSA");
            priv = fact.generatePrivate(keySpec);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
            return null;
        }
        Arrays.fill(clear, (byte) 0);
        return priv;
    }

    public static PublicKey publicKeyFromString(String stored)  {
        byte[] data = Base64.decode(stored);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(data);
        KeyFactory fact;
        PublicKey pub;
        try {
            fact = KeyFactory.getInstance("DSA");
            pub = fact.generatePublic(spec);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
            return null;
        }
        return pub;
    }

    public static String privateKeyToString(PrivateKey priv) {
        KeyFactory fact;
        PKCS8EncodedKeySpec spec;
        byte[] packed;
        String key64 = null;
        try {
            fact = KeyFactory.getInstance("DSA");
            spec = fact.getKeySpec(priv, PKCS8EncodedKeySpec.class);
            packed = spec.getEncoded();
            key64 = new String(Base64.encode(packed));
            Arrays.fill(packed, (byte) 0);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
        return key64;
    }

    public static String publicKeyToString(PublicKey publ) {
        KeyFactory fact;
        X509EncodedKeySpec spec;
        String key = null;
        try {
            fact = KeyFactory.getInstance("DSA");
            spec = fact.getKeySpec(publ, X509EncodedKeySpec.class);
            key = new String(Base64.encode(spec.getEncoded()));
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
        return key;
    }
}