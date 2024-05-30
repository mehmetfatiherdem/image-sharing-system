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

        UserDao userDao = new UserDaoImpl(myDB);
        UserRepository userRepository;
        UserService userService;
        UserServicee userServicee;
        UserController userController;


        TCPClient client;
        try {
            client = new TCPClient(InetAddress.getLocalHost(), Constants.SERVER_PORT);

            Thread clientThread = new Thread(client);
            clientThread.start();

            Thread.sleep(1000);

            //UserDao userDao = new UserDaoImpl(myDB);
            userRepository = new UserRepositoryImpl(userDao);
            userService = new UserServiceImpl(userRepository, client.getSocket());
            userServicee = new UserServiceeImpl(userRepository, client.getSocket());
            userController = new UserController(userService, userServicee);

            new Thread(() -> {
                try {
                    userController.listenServer();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }).start();

            userController.registerr("admin", "admin");

            userController.loginn("admin", "admin");



        } catch (InterruptedException | IOException e) {
            throw new RuntimeException(e);
        }


        UserDao userDao2 = new UserDaoImpl(myDB);
        UserRepository userRepository2;
        UserService userService2;
        UserServicee userServicee2;
        UserController userController2;

        TCPClient client2;
        try {


            client2 = new TCPClient(InetAddress.getLocalHost(), Constants.SERVER_PORT);

            Thread clientThread = new Thread(client2);
            clientThread.start();

            Thread.sleep(1000);

            //UserDao userDao = new UserDaoImpl(myDB);
            userRepository2 = new UserRepositoryImpl(userDao2);
            userService2 = new UserServiceImpl(userRepository2, client2.getSocket());
            userServicee2 = new UserServiceeImpl(userRepository2, client2.getSocket());
            userController2 = new UserController(userService2, userServicee2);

            new Thread(() -> {
                try {
                    userController2.listenServer();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }).start();

            userController2.registerr("xenia", "holt123");

            userController2.loginn("xenia", "holt123");





        } catch (IOException | InterruptedException e) {
            throw new RuntimeException(e);
        }


        UserDao userDao3 = new UserDaoImpl(myDB);
        UserRepository userRepository3;
        UserService userService3;
        UserServicee userServicee3;
        UserController userController3;

        TCPClient client3;
        try {


            client3 = new TCPClient(InetAddress.getLocalHost(), Constants.SERVER_PORT);

            Thread clientThread = new Thread(client3);
            clientThread.start();

            Thread.sleep(1000);

            //UserDao userDao = new UserDaoImpl(myDB);
            userRepository3 = new UserRepositoryImpl(userDao3);
            userService3 = new UserServiceImpl(userRepository3, client3.getSocket());
            userServicee3 = new UserServiceeImpl(userRepository3, client3.getSocket());
            userController3 = new UserController(userService3, userServicee3);

            new Thread(() -> {
                try {
                    userController3.listenServer();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }).start();

            userController3.registerr("mortalh4", "pass123");

            userController3.loginn("mortalh4", "pass123");





        } catch (IOException | InterruptedException e) {
            throw new RuntimeException(e);
        }


        try {
            Thread.sleep(10000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        try {
            String imageName = "glew_logo";
            String imagePath = "src/assets/glew_logo.png";

            userController.postImagee(imageName, imagePath, new ArrayList<>(List.of("xenia")));

            Thread.sleep(8000);

            userController2.downloadImage(imageName);
            userController3.downloadImage(imageName);

        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }


    }

}
