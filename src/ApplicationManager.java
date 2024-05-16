import db.MyDB;
import helper.Constants;
import model.Server;
import socket.TCPClient;

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetAddress;

public class ApplicationManager {
    private static ApplicationManager instance;

    private ApplicationManager() {
    }

    public static ApplicationManager getInstance() {
        if (instance == null) {
            instance = new ApplicationManager();
        }
        return instance;
    }

    public void run() {

        MyDB myDB = MyDB.getInstance();
        myDB.connect();

        Server server;

        try {
            server = Server.getInstance(Constants.SERVER_PORT);
        } catch (Exception e) {
            e.printStackTrace();
            return;
        }

        server.fireUp();

        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }


        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        TCPClient client;
        try {
            client = new TCPClient(InetAddress.getLocalHost(), Constants.SERVER_PORT);

            Thread clientThread = new Thread(client);
            clientThread.start();

            System.out.println("ping");

            Thread.sleep(1000);

            DataOutputStream out = new DataOutputStream(client.getSocket().getOutputStream());
            out.writeUTF("ping");

            DataInputStream in = new DataInputStream(new BufferedInputStream(client.getSocket().getInputStream()));

            if (in.readUTF().equals("pong")) {
                System.out.println("pong");
            } else {
                System.out.println("error");
            }

            out.writeUTF("panic");
            System.out.println("panic");

            if (in.readUTF().equals("pong")) {
                System.out.println("pong");
            } else {
                System.out.println("error");
            }

        } catch (InterruptedException | IOException e) {
            throw new RuntimeException(e);
        }


    }
}
