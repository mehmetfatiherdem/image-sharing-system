package model;

import helper.Constants;
import socket.TCPServer;

import helper.security.Key;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

public class Server {
    private static Server instance;
    private KeyPair keyPair;
    private TCPServer tcpServer;

    private Server() throws NoSuchAlgorithmException {
        keyPair = Key.generateKeyPairs(2048);
        tcpServer = new TCPServer(Constants.SERVER_PORT);
    }

    public static Server getInstance() throws NoSuchAlgorithmException {
        if (instance == null) {
            instance = new Server();
        }
        return instance;
    }

    public void run() {
        Thread serverThread = new Thread(tcpServer);
        serverThread.start();

        if (tcpServer != null) {
            System.out.println("Server is running on port " + tcpServer.getPort());
        }
    }

    public PublicKey getPublicKey() {
        return keyPair.getPublic();
    }

    public TCPServer getTcpServer() {
        return tcpServer;
    }
}
