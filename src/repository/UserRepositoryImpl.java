package repository;

import dao.UserDao;
import dto.UserDTO;
import java.security.PrivateKey;
import java.util.Optional;

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
    public Optional<PrivateKey> getPrivateKey(String username) {
        return userDao.getPrivateKey(username);
    }
    @Override
    public void addPersistentUser(UserDTO user) {
        userDao.addPersistentUser(user);
    }

}
