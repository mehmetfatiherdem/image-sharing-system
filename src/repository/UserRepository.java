package repository;

import dto.UserDTO;

import java.security.PrivateKey;
import java.util.Optional;
import java.util.Set;

public interface UserRepository {
    Optional<UserDTO> getUser(String username);
    Optional<PrivateKey> getPrivateKey(String username); //FIXME: this should be in userlocal
    void addServerNonce(String ip, String nonce);
    Set<String> getServerNonces(String ip);
    void addUser(UserDTO user);
}
