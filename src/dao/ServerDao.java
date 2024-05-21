package dao;

import java.security.PrivateKey;
import java.security.PublicKey;

public interface ServerDao {
    void saveCertificate(byte[] certificateBytes);
    PublicKey getServerPublicKey();
    PrivateKey getServerPrivateKey();
}
