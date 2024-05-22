package model;

import controller.ServerController;
import dao.ServerDao;
import dao.ServerDaoImpl;
import helper.security.Confidentiality;
import repository.ServerRepository;
import repository.ServerRepositoryImpl;
import serverlocal.ServerStorage;
import service.ServerService;
import service.ServerServiceImpl;

import java.net.BindException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

public class Server implements Runnable{

    private static Server instance;
    private KeyPair keyPair;
    private final int port;
    private ServerSocket serverSocket;
    private Socket socket;
    private ServerStorage serverStorage;

    private Server(int port) throws NoSuchAlgorithmException {
        this.port = port;
        keyPair = Confidentiality.generateKeyPairs(2048);
    }

    public static Server getInstance(int port) throws NoSuchAlgorithmException, BindException {
        if (instance == null) {
            instance = new Server(port);
        }
        return instance;
    }

    @Override
    public void run() {
        try {
            serverSocket = new ServerSocket(port);

            socket = serverSocket.accept();

            System.out.println("Server started listening on port " + port);

            ServerDao serverDao = new ServerDaoImpl();
            ServerRepository serverRepository = new ServerRepositoryImpl(serverDao);
            ServerService serverService = new ServerServiceImpl(serverRepository, socket);
            ServerController serverController = new ServerController(serverService);

            serverController.handleRequests();


        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void fireUp() {
        serverStorage = ServerStorage.getInstance();
        serverStorage.setPrivateKey(Confidentiality.getByteArrayFromPrivateKey(keyPair.getPrivate()));
        serverStorage.setPublicKey(Confidentiality.getByteArrayFromPublicKey(keyPair.getPublic()));
        Thread serverThread = new Thread(this);
        serverThread.start();
    }



    // Getters
    public int getPort() {
        return port;
    }
    public ServerSocket getServerSocket() {
        return serverSocket;
    }
    public Socket getSocket() {
        return socket;
    }
    public PublicKey getPublicKey() {
        return keyPair.getPublic();
    }
    public ServerStorage getServerStorage() {
        return serverStorage;
    }

    // remove this
    public KeyPair getKeyPair() {
        return keyPair;
    }

    // Setters
    public void setServerStorage(ServerStorage serverStorage) {
        this.serverStorage = serverStorage;
    }

}
