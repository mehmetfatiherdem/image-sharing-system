package userlocal;

import model.User;

import java.security.PublicKey;

// trying to imitate users own machines to store private key and stuff
public class UserStorage {
    private User user;

    private PublicKey serverPublicKey;

    public UserStorage(User user, PublicKey serverPublicKey) {
        this.user = user;
        this.serverPublicKey = serverPublicKey;
    }

    public User getUser() {
        return user;
    }

    public PublicKey getServerPublicKey() {
        return serverPublicKey;
    }




}
