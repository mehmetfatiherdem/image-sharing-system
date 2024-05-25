package dao;

import dto.UserDTO;
import model.User;

import java.security.PrivateKey;
import java.util.Optional;
import java.util.Set;

public interface UserDao {
    Optional<UserDTO> getUser(String username);
    Optional<PrivateKey> getPrivateKey(String username);
    void addServerNonce(String ip, String nonce);
    Set<String> getServerNonces(String ip);
}
