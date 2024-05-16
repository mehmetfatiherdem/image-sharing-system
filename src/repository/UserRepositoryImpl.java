package repository;

import dao.UserDao;
import model.User;

import java.security.PrivateKey;

public class UserRepositoryImpl implements UserRepository{
    private final UserDao userDao;

    public UserRepositoryImpl(UserDao userDao) {
        this.userDao = userDao;
    }

    @Override
    public User getUser(String username) {
        return userDao.getUser(username);
    }

    @Override
    public PrivateKey getPrivateKey(String username) {
        return userDao.getPrivateKey(username);
    }
}
