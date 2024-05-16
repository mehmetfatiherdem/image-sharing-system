package model;

import helper.security.Confidentiality;

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
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


           DataInputStream in = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
           DataOutputStream out = new DataOutputStream(socket.getOutputStream());


            while (true) {
                String message = in.readUTF();
                if (message.equals("ping")) {
                    out.writeUTF("pong");
                } else {
                    out.writeUTF("error");
                }
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

}
