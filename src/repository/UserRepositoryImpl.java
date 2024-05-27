package repository;

import dao.UserDao;
import dto.UserDTO;
import userlocal.UserStorage;

import java.security.PrivateKey;
import java.util.Optional;
import java.util.Set;

public class UserRepositoryImpl implements UserRepository{
    private final UserDao userDao;

    public UserRepositoryImpl(UserDao userDao) {
        this.userDao = userDao;
    }

    @Override
    public Optional<UserDTO> getPersistentUser(String username) {
        return userDao.getPersistentUser(username);
    }

    @Override
    public Optional<UserDTO> getInMemoryUserWithUsername(String username) {
        return userDao.getInMemoryUserWithUsername(username);
    }

    @Override
    public Optional<UserDTO> getInMemoryUserWithIP(String ip) {
        return userDao.getInMemoryUserWithIP(ip);
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
    public void addInMemoryUser(UserDTO user) {
        userDao.addInMemoryUser(user);
    }

    @Override
    public void addPersistentUser(UserDTO user) {
        userDao.addPersistentUser(user);
    }

    @Override
    public void addUserStorage(UserStorage userStorage) {
        userDao.addUserStorage(userStorage);
    }

    @Override
    public UserStorage getUserStorageWithIP(String ip) {
        return userDao.getUserStorageWithIP(ip);
    }
}
