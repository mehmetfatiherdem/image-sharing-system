package repository;

import dao.ServerDao;

public class ServerRepositoryImpl implements ServerRepository{
    private final ServerDao serverDao;

    public ServerRepositoryImpl(ServerDao serverDao) {
        this.serverDao = serverDao;
    }
    public void addCertificate(byte[] certificateBytes) {
        serverDao.saveCertificate(certificateBytes);
    }
}
