package serverlocal;

import dto.UserDTO;

import java.util.ArrayList;
import java.util.List;

public class ServerStorage {
    private static ServerStorage instance;
    private final List<UserDTO> users = new ArrayList<>();
    private byte[] privateKey;
    private byte[] publicKey;

    private ServerStorage() {
        System.out.println("ServerStorage created");
    }

    public static ServerStorage getInstance() {
        if (instance == null) {
            instance = new ServerStorage();
        }
        return instance;
    }

    public void addUser(UserDTO user) {
        users.add(user);
    }

    // Getters and Setters
    public List<UserDTO> getUsers() {
        return users;
    }
    public void addUsers(List<UserDTO> users) {
        this.users.addAll(users);
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
