package repository;

import dto.UserDTO;

import java.security.PrivateKey;
import java.util.Optional;

public interface UserRepository {
    Optional<UserDTO> getPersistentUser(String username);
    Optional<PrivateKey> getPrivateKey(String username); //FIXME: this should be in userlocal
    void addPersistentUser(UserDTO user);
}
