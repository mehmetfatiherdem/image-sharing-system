package image;

public class Image {
    private String name;
    private byte[] data;

    public Image(String name, byte[] data) {
        this.name = name;
        this.data = data;
    }

    // Getters and setters
    public String getName() {
        return name;
    }
    public void setName(String name) {
        this.name = name;
    }
    public byte[] getData() {
        return data;
    }
    public void setData(byte[] data) {
        this.data = data;
    }
}
