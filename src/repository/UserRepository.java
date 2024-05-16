package repository;

import model.User;

import java.security.PrivateKey;

public interface UserRepository {
    User getUser(String username);
    PrivateKey getPrivateKey(String username);
}
