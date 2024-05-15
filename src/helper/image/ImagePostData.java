package helper.image;

import java.util.Arrays;

public class ImagePostData {
    private final String imageName;
    private final byte[] encryptedImage;
    private final byte[] digitalSignature;
    private final byte[] encryptedAESKey;
    private final byte[] encryptedIV;

    public ImagePostData(String imageName, byte[] encryptedImage, byte[] digitalSignature, byte[] encryptedAESKey, byte[] encryptedIV) {
        this.imageName = imageName;
        this.encryptedImage = encryptedImage;
        this.digitalSignature = digitalSignature;
        this.encryptedAESKey = encryptedAESKey;
        this.encryptedIV = encryptedIV;
    }

    public String getMessageString(){
        return "POST_IMAGE" + " " + imageName + " " + Arrays.toString(encryptedImage) + " " + Arrays.toString(digitalSignature) + " "
                + Arrays.toString(encryptedAESKey) + " " + Arrays.toString(encryptedIV);
    }

    // Getters
    public String getImageName() {
        return imageName;
    }

    public byte[] getEncryptedImage() {
        return encryptedImage;
    }

    public byte[] getDigitalSignature() {
        return digitalSignature;
    }

    public byte[] getEncryptedAESKey() {
        return encryptedAESKey;
    }

    public byte[] getEncryptedIV() {
        return encryptedIV;
    }
}
