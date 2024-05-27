package dao;

import dto.UserDTO;
import model.Certificate;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;
import java.util.Set;

public interface ServerDao {
    void saveCertificate(Certificate certificate, String ip);
    PublicKey getServerPublicKey();
    PrivateKey getServerPrivateKey();
    Set<String> getNoncesUsed(String ip);
    void addNonceUsed(String ip, String nonce);
    void addUser(UserDTO user);
    List<UserDTO> getUsers();
    UserDTO getUserWithIP(String ip);
    UserDTO getUserWithUsername(String username);

}
