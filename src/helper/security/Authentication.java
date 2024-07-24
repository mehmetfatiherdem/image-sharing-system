package helper.security;

import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Base64;

public class Authentication {

    public static byte[] sign(byte[] data, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    public static boolean verify(byte[] data, byte[] signature, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature sign = Signature.getInstance("SHA256withRSA");
        sign.initVerify(publicKey);
        sign.update(data);
        return sign.verify(signature);
    }

    public static byte[] generateMACKey() throws Exception {
        SecureRandom random = SecureRandom.getInstanceStrong();
        byte[] keyBytes = new byte[16];
        random.nextBytes(keyBytes);
        return keyBytes;
    }

    // diffie helman key generation
    public static byte[] generateSharedSecret(PrivateKey privateKey, PublicKey publicKey) throws Exception {
        KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(publicKey, true);
        return keyAgreement.generateSecret();
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

    public static byte[] hashPassword(String password, byte[] salt) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 32);
        SecretKey key = factory.generateSecret(spec);
        return key.getEncoded();
    }

    public static boolean verifyPassword(String password, byte[] salt, byte[] receivedHash) throws Exception {
        byte[] generatedHash = hashPassword(password, salt);
        return Arrays.equals(generatedHash, receivedHash);
    }

    public static byte[] generateSalt() throws NoSuchAlgorithmException {
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return salt;
    }

    public static String generateNonce() {
        SecureRandom random = new SecureRandom();
        byte[] nonce = new byte[16];
        random.nextBytes(nonce);
        return Base64.getEncoder().encodeToString(nonce);
    }

    private static String intToIP(int ipAddress) {
        return ((ipAddress >> 24) & 0xFF) + "." + ((ipAddress >> 16) & 0xFF) + "."
                + ((ipAddress >> 8) & 0xFF) + "." + (ipAddress & 0xFF);
    }


    public static String generateSessionID() {
        SecureRandom random = new SecureRandom();
        return new BigInteger(130, random).toString(32);
    }
}
