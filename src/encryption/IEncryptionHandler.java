package encryption;

public interface IEncryptionHandler {
    byte[] encrypt(String message, byte[] key) throws Exception;
    byte[] decrypt(byte[] message, byte[] key) throws Exception;
    byte[] getKey();
}
