package dao;

import dto.UserDTO;
import helper.image.ImageDownloadData;
import helper.image.ImageMetaData;
import helper.security.Confidentiality;
import model.Certificate;
import serverlocal.ServerStorage;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class ServerDaoImpl implements ServerDao{

    private final ServerStorage serverStorage;

    public ServerDaoImpl(ServerStorage serverStorage) {
        this.serverStorage = serverStorage;
    }

    @Override
    public void saveImage(ImageMetaData metaData, ImageDownloadData imageDownloadData) {
        serverStorage.addImage(metaData, imageDownloadData);
    }
    @Override
    public Map<ImageMetaData, ImageDownloadData> getImageByName(String imageName) {
        Map<ImageMetaData, ImageDownloadData> images = new HashMap<>();
        for (var entry : serverStorage.getImages().entrySet()) {
            if (entry.getValue().getImageName().equals(imageName)) {
                images.put(entry.getKey(), entry.getValue());
            }
        }
        return images;
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
                return user.getNonceUsed();
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
    public UserDTO getUserWithIP(String ip) {
        var users = serverStorage.getUsers();
        for (var user : users) {
            if (user.getIP().equals(ip)) {
                return user;
            }
        }

        return null;
    }

    @Override
    public UserDTO getUserWithUsername(String username) {
        var users = serverStorage.getUsers();
        for (var user: users) {
            if (user.getUsername().equals(username)) {
                return user;
            }
        }
        return null;
    }
}
