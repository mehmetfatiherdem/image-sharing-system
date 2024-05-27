import controller.UserController;
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
import java.util.ArrayList;
import java.util.List;

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
            UserService userService = new UserServiceImpl(userRepository, client.getSocket());
            UserController userController = new UserController(userService);

            userController.register("admin", "admin");
            userController.login("admin", "admin");


            String imageName = "glew_logo.png";
            String imagePath = "assets";

           userController.postImage(imageName, imagePath, new ArrayList<>(List.of("ALL")));


        } catch (InterruptedException | IOException e) {
            throw new RuntimeException(e);
        }


    }

}
