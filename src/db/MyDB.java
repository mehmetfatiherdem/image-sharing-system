package db;

import dto.UserDTO;
import entity.UserEntity;
import model.Certificate;
import model.User;
import userlocal.UserStorage;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;

public class MyDB {
    private static MyDB instance;
    private final ArrayList<UserDTO> inMemoryUsers = new ArrayList<>();
    private final ArrayList<UserEntity> persistentUsers = new ArrayList<>();
    private final Set<UserStorage> userStorages = new HashSet<>();

    private MyDB() {

    }

    public static MyDB getInstance() {
        if (instance == null) {
            instance = new MyDB();
        }
        return instance;
    }

    public void connect() {
        System.out.println("Connected to MyDB");
    }

    public void addInMemoryUser(UserDTO userDTO) {
        inMemoryUsers.add(userDTO);
    }

    public void addPersistentUser(String IP, String username, byte[] password, byte[] passwordSalt, Certificate certificate) {
        try{
            UserEntity userEntity =
                    new UserEntity(IP, username, password, passwordSalt, certificate);
            persistentUsers.add(userEntity);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void addUserStorage(UserStorage userStorage) {
        userStorages.add(userStorage);
    }

    public Set<UserStorage> getUserStorages() {
        return userStorages;
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
