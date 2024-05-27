package model;

import dao.ServerDao;
import dao.ServerDaoImpl;
import helper.security.Confidentiality;
import repository.ServerRepository;
import repository.ServerRepositoryImpl;
import serverlocal.ServerStorage;
import service.ServerServiceImpl;

import java.net.BindException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Server implements Runnable{

    private static Server instance;
    private KeyPair keyPair;
    private final int port;
    private ServerSocket serverSocket;
    private Socket socket;
    private ServerStorage serverStorage;
    private static Set<ServerServiceImpl> clientHandlers = ConcurrentHashMap.newKeySet();


    private Server(int port) throws NoSuchAlgorithmException {
        this.port = port;
        keyPair = Confidentiality.generateRSAKeyPairs(2048);
        // keyPair = Confidentiality.generateDHKeyPairs();
    }

    public static Server getInstance(int port) throws NoSuchAlgorithmException, BindException {
        if (instance == null) {
            instance = new Server(port);
        }
        return instance;
    }

    @Override
    public void run() {
        ExecutorService threadPool = Executors.newFixedThreadPool(10);

        try {
            serverSocket = new ServerSocket(port);
            System.out.println("Server started listening on port " + port);

            serverStorage = ServerStorage.getInstance();
            serverStorage.setPrivateKey(Confidentiality.getByteArrayFromPrivateKey(keyPair.getPrivate()));
            serverStorage.setPublicKey(Confidentiality.getByteArrayFromPublicKey(keyPair.getPublic()));
            ServerDao serverDao = new ServerDaoImpl(serverStorage);
            ServerRepository serverRepository = new ServerRepositoryImpl(serverDao);


            while (true) {

                socket = serverSocket.accept();
                ServerServiceImpl serverService = new ServerServiceImpl(serverRepository, socket);
                clientHandlers.add(serverService);
                threadPool.execute(serverService);

            }



        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void fireUp() {

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
