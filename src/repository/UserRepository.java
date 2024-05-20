package repository;

import dto.UserDTO;

import java.security.PrivateKey;
import java.util.Optional;

public interface UserRepository {
    Optional<UserDTO> getUser(String username);
    Optional<PrivateKey> getPrivateKey(String username); //FIXME: this should be in userlocal
}
