package dao;

import model.User;

import java.security.PrivateKey;

public interface UserDao {
    User getUser(String username);
    PrivateKey getPrivateKey(String username);
}
