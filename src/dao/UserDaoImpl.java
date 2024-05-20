package dao;

import db.MyDB;
import dto.UserDTO;

import java.security.PrivateKey;
import java.util.Optional;

public class UserDaoImpl implements UserDao{

    private final MyDB myDB;

    public UserDaoImpl(MyDB myDB) {
        this.myDB = myDB;
    }


    @Override
    public Optional<UserDTO> getUser(String username) {
        var users = myDB.getPersistentUsers();

        var user = users.stream()
                .filter(u -> u.getUsername().equals(username))
                .findFirst()
                .orElse(null);

        if (user == null) {
            System.out.println("User not found");
            return Optional.empty();
        }


        return Optional.of(new UserDTO(user.getUsername(), user.getPassword()));

    }

    @Override
    public Optional<PrivateKey> getPrivateKey(String username) {
        var users = myDB.getPersistentUsers();

        //TODO: get this from user local storage
        /*
        return users.stream()
                .filter(user -> user.getUsername().equals(username))
                .findFirst()
                .map(user -> user.getKeyPair().getPrivate())
                .orElse(null);

         */


        return Optional.empty();
    }
}
