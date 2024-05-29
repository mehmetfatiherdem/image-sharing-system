package serverlocal;

import dto.UserDTO;
import helper.image.ImageDownloadData;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

public class ServerStorage {
    private static ServerStorage instance;
    private final List<UserDTO> users = new ArrayList<>();
    private byte[] privateKey;
    private byte[] publicKey;
    private final HashMap<String, ImageDownloadData> images = new HashMap<>();

    private ServerStorage() {
        System.out.println("ServerStorage created");
    }

    public static ServerStorage getInstance() {
        if (instance == null) {
            instance = new ServerStorage();
        }
        return instance;
    }


    public void addImage(String ownerName, ImageDownloadData imageDownloadData) {
        images.put(ownerName, imageDownloadData);
    }

    public HashMap<String, ImageDownloadData> getImages() {
        return images;
    }

    public void addUser(UserDTO user) {
        users.add(user);
    }

    // Getters and Setters
    public List<UserDTO> getUsers() {
        return users;
    }

    public byte[] getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(byte[] privateKey) {
        this.privateKey = privateKey;
    }

    public byte[] getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(byte[] publicKey) {
        this.publicKey = publicKey;
    }
}
