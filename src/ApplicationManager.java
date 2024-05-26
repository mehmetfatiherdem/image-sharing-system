import controller.AuthController;
import dao.UserDao;
import dao.UserDaoImpl;
import db.MyDB;
import helper.Constants;
import model.Server;

import repository.UserRepository;
import repository.UserRepositoryImpl;
import service.*;
import socket.TCPClient;

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




        TCPClient client;
        try {
            client = new TCPClient(InetAddress.getLocalHost(), Constants.SERVER_PORT);

            Thread clientThread = new Thread(client);
            clientThread.start();

            Thread.sleep(1000);

            UserDao userDao = new UserDaoImpl(myDB);
            UserRepository userRepository = new UserRepositoryImpl(userDao);
            AuthService authService = new AuthServiceImpl(userRepository, client.getSocket());
            AuthController authController = new AuthController(authService);

            authController.register("admin", "admin");
            //authController.login("admin", "admin");


        } catch (InterruptedException | IOException e) {
            throw new RuntimeException(e);
        }


    }
}
