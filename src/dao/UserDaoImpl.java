package dao;

import db.MyDB;
import model.User;

import java.security.PrivateKey;

public class UserDaoImpl implements UserDao{

    private final MyDB myDB;

    public UserDaoImpl(MyDB myDB) {
        this.myDB = myDB;
    }


    @Override
    public User getUser(String username) {
        var users = myDB.getPersistentUsers();
        return users.stream()
                .filter(user -> user.getUsername().equals(username))
                .findFirst()
                .orElse(null);
    }

    @Override
    public PrivateKey getPrivateKey(String username) {
        var users = myDB.getPersistentUsers();
        return users.stream()
                .filter(user -> user.getUsername().equals(username))
                .findFirst()
                .map(user -> user.getKeyPair().getPrivate())
                .orElse(null);
    }
}
