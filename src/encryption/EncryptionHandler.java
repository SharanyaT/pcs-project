package encryption;

import org.whispersystems.curve25519.Curve25519;
import org.whispersystems.curve25519.Curve25519KeyPair;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.*;

public class EncryptionHandler {

    public static byte[] iv = new SecureRandom().generateSeed(16);

    public static void main(String[] args) {
//        Security.removeProvider("SunEC");
//        Security.removeProvider("SUN");
//        Security.removeProvider("SunJSSE");
//        // ...
//        Security.addProvider(new BouncyCastleProvider());
        String plainText = "Look mah, I'm a message!";
        System.out.println("Original plaintext message: " + plainText);

        // Initialize two key pairs
        KeyPair keyPairA = generateKeyPair();
        KeyPair keyPairB = generateKeyPair();

        System.out.println("Key a: " + keyPairA.getPrivate());

        // Create two AES secret keys to encrypt/decrypt the message
        SecretKey secretKeyA = generateSharedSecret(keyPairA.getPrivate(),
                keyPairB.getPublic());
        SecretKey secretKeyB = generateSharedSecret(keyPairB.getPrivate(),
                keyPairA.getPublic());

        System.out.println("Secret key: " + secretKeyA);
        // Encrypt the message using 'secretKeyA'
        String cipherText = encryptString(secretKeyA, plainText);
        System.out.println("Encrypted cipher text: " + cipherText);

        // Decrypt the message using 'secretKeyB'
//        String decryptedPlainText = decryptString(secretKeyB, cipherText);
//        System.out.println("Decrypted cipher text: " + decryptedPlainText);
    }

    public static String encryptString(SecretKey secretKey, String plainText){
        try {
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            byte[] plainTextBytes = plainText.getBytes("UTF-8");
            byte[] cipherText;

            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
            cipherText = new byte[cipher.getOutputSize(plainTextBytes.length)];
            int encryptLength = cipher.update(plainTextBytes, 0,
                    plainTextBytes.length, cipherText, 0);
            encryptLength += cipher.doFinal(cipherText, encryptLength);

            return bytesToHex(cipherText);
        } catch (NoSuchAlgorithmException
                | NoSuchPaddingException | InvalidKeyException
                | InvalidAlgorithmParameterException
                | UnsupportedEncodingException | ShortBufferException
                | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static byte[] encrypt(String message, byte[] key) throws Exception{
        String algorithm="HmacSHA256";
        Mac mac = Mac.getInstance(algorithm);
        mac.init(new SecretKeySpec(key, algorithm));
        return mac.doFinal(message.getBytes("UTF8"));
    }

    public static byte[] decrypt(byte[] message, byte[] key) {
        return null;
    }

//    public static Curve25519KeyPair generateKeyPair() {
//        return Curve25519.getInstance(Curve25519.BEST).generateKeyPair();
//    }

//    public static byte[] generateSecret() throws NoSuchAlgorithmException{
//        // Generate ephemeral ECDH keypair
//        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
//        kpg.initialize(256);
//        KeyPair kp = kpg.generateKeyPair();
//        byte[] ourPk = kp.getPublic().getEncoded();
//        return ourPk;
//    }

    public static KeyPair generateKeyPair() {
        // Generate ephemeral ECDH keypair
        try{
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(256);
            KeyPair kp = kpg.generateKeyPair();
//        byte[] ourPk = kp.getPublic().getEncoded();
            return kp;
        } catch (NoSuchAlgorithmException e){
            return null;
        }
    }

    public static SecretKey generateSharedSecret(PrivateKey privateKey, PublicKey publicKey) {
        try {
            KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
            keyAgreement.init(privateKey);
            keyAgreement.doPhase(publicKey, true);

            SecretKey key = keyAgreement.generateSecret("AES");
            return key;
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return null;
        }
    }

    public static String bytesToHex(byte[] data) {
        return bytesToHex(data, data.length);
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


}
