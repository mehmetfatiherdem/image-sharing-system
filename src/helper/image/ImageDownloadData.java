package helper.image;

import java.util.Arrays;
import java.util.HashMap;

public class ImageDownloadData {
    private String imageName;
    private byte[] encryptedImage;
    private byte[] digitalSignature;
    private byte[] iv;
    private HashMap<String, byte[]> encryptedAESKeys = new HashMap<>();
    private byte[] certificatePublicKey;

    public ImageDownloadData(String imageName, byte[] encryptedImage, byte[] digitalSignature, byte[] certificatePublicKey, byte[] iv) {
        this.imageName = imageName;
        this.encryptedImage = encryptedImage;
        this.digitalSignature = digitalSignature;
        this.certificatePublicKey = certificatePublicKey;
        this.iv = iv;
    }

    // Getters setters
    public byte[] getEncryptedImage() {
        return encryptedImage;
    }
    public void setEncryptedImage(byte[] encryptedImage) {
        this.encryptedImage = encryptedImage;
    }

    public byte[] getDigitalSignature() {
        return digitalSignature;
    }
    public void setDigitalSignature(byte[] digitalSignature) {
        this.digitalSignature = digitalSignature;
    }

    public HashMap<String, byte[]> getEncryptedAESKeys() {
        return encryptedAESKeys;
    }
    public void addEncryptedAESKey(String username, byte[] encryptedAESKey) {
        this.encryptedAESKeys.put(username, encryptedAESKey);
    }

    public byte[] getCertificatePublicKey() {
        return certificatePublicKey;
    }
    public void setCertificatePublicKey(byte[] certificatePublicKey) {
        this.certificatePublicKey = certificatePublicKey;
    }

    public String getImageName() {
        return imageName;
    }
    public void setImageName(String imageName) {
        this.imageName = imageName;
    }
    public byte[] getIv() {
        return iv;
    }
    public void setIv(byte[] iv) {
        this.iv = iv;
    }
}
