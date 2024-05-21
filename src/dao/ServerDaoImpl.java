package dao;

import helper.security.Confidentiality;
import serverlocal.ServerStorage;

import java.security.PrivateKey;
import java.security.PublicKey;

public class ServerDaoImpl implements ServerDao{

    private final ServerStorage serverStorage;

    public ServerDaoImpl() {
        serverStorage = ServerStorage.getInstance();
    }

    public void saveCertificate(byte[] certificateBytes) {
        // TODO: Save certificate to database
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
}
