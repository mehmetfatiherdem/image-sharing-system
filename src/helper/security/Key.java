package helper.security;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;

public class Key {
    public static KeyPair generateKeyPairs(int keySize) throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keySize);
        return keyPairGenerator.generateKeyPair();
    }

    public static SecretKey generateAESKey(int keySize) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(keySize);
        return keyGenerator.generateKey();
    }

    public static byte[] generateIV(int ivSizeByte) {
        byte[] iv = new byte[ivSizeByte];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(iv);
        return iv;
    }

    public static byte[] generateMACKey() throws Exception {
        SecureRandom random = SecureRandom.getInstanceStrong();
        byte[] keyBytes = new byte[16];
        random.nextBytes(keyBytes);
        return keyBytes;
    }

    public static byte[] generateMAC(byte[] message, byte[] key) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        mac.update(message);
        return mac.doFinal();
    }

    public static boolean verifyMAC(String message, byte[] receivedMac, byte[] key) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "HmacSHA256");
        mac.init(secretKeySpec);
        mac.update(message.getBytes());
        byte[] calculatedMac = mac.doFinal();
        return Arrays.equals(calculatedMac, receivedMac);
    }

    public static String appendMACToMessage(byte[] message, byte[] mac) throws Exception {
        return message + " " + Base64.getEncoder().encodeToString(mac);
    }

    public static byte[] generateMessageDigest(byte[] data) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        return messageDigest.digest(data);
    }

    public static byte[] encryptWithAES(byte[] data, SecretKey secretKey, byte[] iv) throws NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
        return cipher.doFinal(data);
    }

    public static byte[] decryptWithAES(byte[] data, SecretKey secretKey, byte[] iv) throws NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
        return cipher.doFinal(data);
    }

    public static byte[] encryptWithSymmetricKey(byte[] data, PublicKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    public static byte[] decryptWithSymmetricKey(byte[] encryptedData, PrivateKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, key);
        var e = new SecretKeySpec(cipher.doFinal(encryptedData), "AES");
        return e.getEncoded();
    }

}
