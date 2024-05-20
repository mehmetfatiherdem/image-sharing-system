package dao;

import java.security.PublicKey;

public class ServerDaoImpl implements ServerDao{
    public void saveCertificate(byte[] certificateBytes) {
        // TODO: Save certificate to database
    }

    @Override
    public PublicKey getServerPublicKey() {
        return null;
    }
}
