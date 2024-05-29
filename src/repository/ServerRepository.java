package repository;

import dto.UserDTO;
import helper.image.ImageDownloadData;
import model.Certificate;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;
import java.util.Set;

public interface ServerRepository {
    void saveImage(String ownerName, ImageDownloadData imageDownloadData);
    ImageDownloadData getImageByName(String imageName);
    void addCertificate(Certificate certificate, String ip);
    PublicKey getPublicKey();
    PrivateKey getPrivateKey();
    Set<String> getNoncesUsed(String ip);
    void addNonceUsed(String ip, String nonce);
    List<UserDTO> getUsers();
    void addUser(UserDTO user);
    UserDTO getUserWithIP(String ip);
    UserDTO getUserWithUsername(String username);
}
