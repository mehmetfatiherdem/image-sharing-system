package dao;

import dto.UserDTO;
import helper.security.Confidentiality;
import model.Certificate;
import serverlocal.ServerStorage;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;
import java.util.Set;

public class ServerDaoImpl implements ServerDao{

    private final ServerStorage serverStorage;

    public ServerDaoImpl() {
        serverStorage = ServerStorage.getInstance();
    }

    public void saveCertificate(Certificate certificate, String ip) {
        var users = serverStorage.getUsers();
        for (var user : users) {
            if (user.getIP().equals(ip)) {
                user.setCertificate(certificate);
            }
        }
    }

    @Override
    public PublicKey getServerPublicKey() {
        PublicKey publicKey = null;
        try {
            publicKey = Confidentiality.getPublicKeyFromByteArray(serverStorage.getPublicKey());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return publicKey;
    }

    @Override
    public PrivateKey getServerPrivateKey() {
        PrivateKey privateKey = null;
        try {
            privateKey = Confidentiality.getPrivateKeyFromByteArray(serverStorage.getPrivateKey());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return privateKey;
    }

    @Override
    public Set<String> getNoncesUsed(String ip) {
        var users = serverStorage.getUsers();
        for (var user : users) {
            if (user.getIP().equals(ip)) {
                return user.getNoncesUsed();
            }
        }

        return null;
    }

    @Override
    public void addNonceUsed(String ip, String nonce) {
        var users = serverStorage.getUsers();
        for (var user : users) {
            if (user.getIP().equals(ip)) {
                user.addNonceUsed(nonce);
            }
        }
    }

    @Override
    public void addUser(UserDTO user) {
        serverStorage.addUser(user);
    }

    @Override
    public List<UserDTO> getUsers() {
        return serverStorage.getUsers();
    }

    @Override
    public UserDTO getUser(String ip) {
        var users = serverStorage.getUsers();
        for (var user : users) {
            if (user.getIP().equals(ip)) {
                return user;
            }
        }

        return null;
    }
}
