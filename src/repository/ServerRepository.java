package repository;

import java.security.PublicKey;

public interface ServerRepository {
    void addCertificate(byte[] certificate);
    PublicKey getPublicKey();
}
