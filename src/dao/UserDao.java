package dao;

import dto.UserDTO;

import java.security.PrivateKey;
import java.util.Optional;

public interface UserDao {
    Optional<UserDTO> getPersistentUser(String username);
   // Optional<UserDTO> getInMemoryUserWithIP(String ip);
    Optional<PrivateKey> getPrivateKey(String username);
   // void addInMemoryUser(UserDTO user);
    void addPersistentUser(UserDTO user);
}
