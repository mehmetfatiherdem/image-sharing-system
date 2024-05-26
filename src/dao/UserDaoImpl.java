package dao;

import db.MyDB;
import dto.UserDTO;
import userlocal.UserStorage;

import java.security.PrivateKey;
import java.util.Optional;
import java.util.Set;

public class UserDaoImpl implements UserDao{

    private final MyDB myDB;
    public UserDaoImpl(MyDB myDB) {
        this.myDB = myDB;
    }


    @Override
    public Optional<UserDTO> getPersistentUser(String username) {
        var users = myDB.getPersistentUsers();

        var user = users.stream()
                .filter(u -> u.getUsername().equals(username))
                .findFirst()
                .orElse(null);

        if (user == null) {
            System.out.println("User not found");
            return Optional.empty();
        }


        return Optional.of(new UserDTO(user.getUsername(), user.getPassword(), user.getIP()));

    }

    @Override
    public Optional<UserDTO> getInMemoryUserWithUsername(String username) {
        var users = myDB.getInMemoryUsers();

        var user = users.stream()
                .filter(u -> u.getUsername().equals(username))
                .findFirst()
                .orElse(null);

        if (user == null) {
            System.out.println("User not found");
            return Optional.empty();
        }

        return Optional.of(user);
    }

    @Override
    public Optional<UserDTO> getInMemoryUserWithIP(String ip) {
        var users = myDB.getInMemoryUsers();

        var user = users.stream()
                .filter(u -> u.getIP().equals(ip))
                .findFirst()
                .orElse(null);

        if (user == null) {
            System.out.println("User not found");
            return Optional.empty();
        }

        return Optional.of(user);
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

    @Override
    public void addServerNonce(String ip, String nonce) {
        myDB.getInMemoryUsers().stream()
                .filter(user -> user.getIP().equals(ip))
                .findFirst()
                .ifPresent(user -> user.getUserStorage().addServerNonceUsed(nonce));
    }

    @Override
    public Set<String> getServerNonces(String ip) {
        return myDB.getInMemoryUsers().stream()
                .filter(user -> user.getIP().equals(ip))
                .findFirst()
                .map(user -> user.getUserStorage().getServerNoncesUsed())
                .orElse(null);
    }

    @Override
    public void addInMemoryUser(UserDTO user) {
        myDB.addInMemoryUser(user);
    }

    @Override
    public void addPersistentUser(UserDTO user) {
        myDB.addPersistentUser(user.getIP(), user.getUsername(), user.getPassword(), user.getPasswordSalt(), user.getCertificate());
    }
}
