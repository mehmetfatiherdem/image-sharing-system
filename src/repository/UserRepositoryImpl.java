package repository;

import dao.UserDao;

public class UserRepositoryImpl implements UserRepository{
    private final UserDao userDao;

    public UserRepositoryImpl(UserDao userDao) {
        this.userDao = userDao;
    }
}
