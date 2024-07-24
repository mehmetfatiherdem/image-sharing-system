package db;

import dto.UserDTO;
import entity.UserEntity;
import model.Certificate;
import model.User;

import java.util.ArrayList;


public class MyDB {
    private static MyDB instance;
    // private final ArrayList<UserDTO> inMemoryUsers = new ArrayList<>();
    private final ArrayList<UserEntity> persistentUsers = new ArrayList<>();

    private MyDB() {

    }

    public static synchronized  MyDB getInstance() {
        if (instance == null) {
            instance = new MyDB();
        }
        return instance;
    }

    public synchronized  void connect() {
        System.out.println("Connected to MyDB");
    }

    /*
    public synchronized  void addInMemoryUser(UserDTO userDTO) {
        inMemoryUsers.add(userDTO);
    }

     */

    public synchronized  void addPersistentUser(String username, byte[] password, byte[] passwordSalt, Certificate certificate) {
        try{
            UserEntity userEntity =
                    new UserEntity(username, password, passwordSalt, certificate);
            persistentUsers.add(userEntity);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
/*
    public synchronized  ArrayList<UserDTO> getInMemoryUsers() {
        return inMemoryUsers;
    }


 */
    public synchronized  ArrayList<UserEntity> getPersistentUsers() {
        return persistentUsers;
    }
/*
    public synchronized  void removeInMemoryUser(UserDTO userDTO) {
        inMemoryUsers.remove(userDTO);
    }


 */
    public synchronized  void removePersistentUser(User user) {
        persistentUsers.remove(user);
    }
}
