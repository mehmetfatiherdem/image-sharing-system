package serverlocal;

import dto.UserDTO;
import helper.image.ImageDownloadData;
import helper.image.ImageMetaData;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

public class ServerStorage {
    private static ServerStorage instance;
    private final List<UserDTO> users = new ArrayList<>();
    private byte[] privateKey;
    private byte[] publicKey;
    private final HashMap<ImageMetaData, ImageDownloadData> images = new HashMap<>();

    private ServerStorage() {
        System.out.println("ServerStorage created");
    }

    public static synchronized ServerStorage getInstance() {
        if (instance == null) {
            instance = new ServerStorage();
        }
        return instance;
    }


    public synchronized void addImage(ImageMetaData imageMetaData, ImageDownloadData imageDownloadData) {
        images.put(imageMetaData, imageDownloadData);
    }

    public synchronized HashMap<ImageMetaData, ImageDownloadData> getImages() {
        return images;
    }

    public synchronized void addUser(UserDTO user) {
        users.add(user);
    }

    // Getters and Setters
    public synchronized List<UserDTO> getUsers() {
        return users;
    }

    public synchronized byte[] getPrivateKey() {
        return privateKey;
    }

    public synchronized void setPrivateKey(byte[] privateKey) {
        this.privateKey = privateKey;
    }

    public synchronized byte[] getPublicKey() {
        return publicKey;
    }

    public synchronized void setPublicKey(byte[] publicKey) {
        this.publicKey = publicKey;
    }
}
