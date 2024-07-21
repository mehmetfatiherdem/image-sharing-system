package repository;

import dto.UserDTO;

import java.security.PrivateKey;
import java.util.Optional;

public interface UserRepository {
    Optional<UserDTO> getPersistentUser(String username);
    Optional<UserDTO> getInMemoryUserWithIP(String ip);
    Optional<PrivateKey> getPrivateKey(String username); //FIXME: this should be in userlocal
    void addInMemoryUser(UserDTO user);
    void addPersistentUser(UserDTO user);
}
