package helper.image;

import java.util.Arrays;

public class ImageDownloadData {
    private final byte[] encryptedImage;
    private final byte[] digitalSignature;
    private final byte[] encryptedAESKey;
    private final byte[] certificatePublicKey;

    public ImageDownloadData(byte[] encryptedImage, byte[] digitalSignature, byte[] encryptedAESKey, byte[] certificatePublicKey) {
        this.encryptedImage = encryptedImage;
        this.digitalSignature = digitalSignature;
        this.encryptedAESKey = encryptedAESKey;
        this.certificatePublicKey = certificatePublicKey;
    }

    public String getMessageString(){
        return "IMAGE_DATA" + " " + Arrays.toString(encryptedImage) + " " + Arrays.toString(digitalSignature) + " "
                + Arrays.toString(encryptedAESKey) + " " + Arrays.toString(certificatePublicKey);
    }

    // Getters
    public byte[] getEncryptedImage() {
        return encryptedImage;
    }

    public byte[] getDigitalSignature() {
        return digitalSignature;
    }

    public byte[] getEncryptedAESKey() {
        return encryptedAESKey;
    }

    public byte[] getCertificatePublicKey() {
        return certificatePublicKey;
    }

}
