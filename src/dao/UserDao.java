package dao;

import dto.UserDTO;
import model.User;

import java.security.PrivateKey;
import java.util.Optional;

public interface UserDao {
    Optional<UserDTO> getUser(String username);
    Optional<PrivateKey> getPrivateKey(String username);
}
