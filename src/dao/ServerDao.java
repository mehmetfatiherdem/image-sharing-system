package dao;

import java.security.PublicKey;

public interface ServerDao {
    void saveCertificate(byte[] certificateBytes);
    PublicKey getServerPublicKey();
}
