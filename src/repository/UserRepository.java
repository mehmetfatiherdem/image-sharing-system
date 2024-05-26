package repository;

import dto.UserDTO;

import java.security.PrivateKey;
import java.util.Optional;
import java.util.Set;

public interface UserRepository {
    Optional<UserDTO> getPersistentUser(String username);
    Optional<UserDTO> getInMemoryUserWithUsername(String username);
    Optional<UserDTO> getInMemoryUserWithIP(String ip);
    Optional<PrivateKey> getPrivateKey(String username); //FIXME: this should be in userlocal
    void addServerNonce(String ip, String nonce);
    Set<String> getServerNonces(String ip);
    void addInMemoryUser(UserDTO user);
    void addPersistentUser(UserDTO user);
}
