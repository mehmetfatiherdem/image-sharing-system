package helper.image;

import java.io.FileInputStream;

public class ImageFileIO {
    private final String imagePath;
    public ImageFileIO(String imagePath) {
        this.imagePath = imagePath;
    }

    public byte[] getImageBytes() {
        try {
            FileInputStream fileInputStream = new FileInputStream(imagePath);
            byte[] imageBytes = fileInputStream.readAllBytes();
            fileInputStream.close();
            return imageBytes;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

}
