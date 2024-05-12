package service;
import helper.security.Auth;
import model.Certificate;
import repository.UserRepository;

import java.security.PublicKey;

public class UserServiceImpl implements UserService {
    private final UserRepository userRepository;

    public UserServiceImpl(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public boolean verifyCertificate(Certificate certificate, PublicKey publicKey) {
        boolean isVerified = false;

        try {
            isVerified = Auth.verify(certificate, publicKey);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return isVerified;
    }
}
