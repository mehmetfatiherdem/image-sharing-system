package db;

import dto.UserDTO;
import entity.UserEntity;
import model.User;

import java.util.ArrayList;

public class MyDB {
    private static MyDB instance;
    private final ArrayList<UserDTO> inMemoryUsers = new ArrayList<>();
    private final ArrayList<UserEntity> persistentUsers = new ArrayList<>();

    private MyDB() {

    }

    public static MyDB getInstance() {
        if (instance == null) {
            instance = new MyDB();
        }
        return instance;
    }

    // this has no meaningful purpose in life but ain't that sick??
    public void connect() {
        System.out.println("Connected to MyDB");
    }

    public void addInMemoryUser(UserDTO userDTO) {
        inMemoryUsers.add(userDTO);
    }

    public void addPersistentUser(User user) {
        try{
            UserEntity userEntity =
                    new UserEntity(user.getUsername(), user.getPassword(), user.getPasswordSalt(), user.getKeyPair());
            persistentUsers.add(userEntity);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public ArrayList<UserDTO> getInMemoryUsers() {
        return inMemoryUsers;
    }

    public ArrayList<UserEntity> getPersistentUsers() {
        return persistentUsers;
    }

    public void removeInMemoryUser(UserDTO userDTO) {
        inMemoryUsers.remove(userDTO);
    }

    public void removePersistentUser(User user) {
        persistentUsers.remove(user);
    }
}
