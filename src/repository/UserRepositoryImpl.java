package repository;

import dao.UserDao;
import dto.UserDTO;

import java.security.PrivateKey;
import java.util.Optional;
import java.util.Set;

public class UserRepositoryImpl implements UserRepository{
    private final UserDao userDao;

    public UserRepositoryImpl(UserDao userDao) {
        this.userDao = userDao;
    }

    @Override
    public Optional<UserDTO> getUser(String username) {
        return userDao.getUser(username);
    }

    @Override
    public Optional<PrivateKey> getPrivateKey(String username) {
        return userDao.getPrivateKey(username);
    }

    @Override
    public void addServerNonce(String ip, String nonce) {
        userDao.addServerNonce(ip, nonce);
    }
    @Override
    public Set<String> getServerNonces(String ip) {
        return userDao.getServerNonces(ip);
    }

    @Override
    public void addUser(UserDTO user) {
        userDao.addUser(user);
    }
}
