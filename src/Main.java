import com.sun.net.httpserver.HttpServer;
import controller.UserController;
import dao.UserDao;
import dao.UserDaoImpl;
import db.MyDB;
import frontend.MyHTTPServer;
import helper.Constants;
import helper.security.Authentication;
import helper.security.Confidentiality;
import model.Server;
import repository.UserRepository;
import repository.UserRepositoryImpl;
import service.UserService;
import service.UserServiceImpl;
import service.UserServicee;
import service.UserServiceeImpl;
import socket.TCPClient;

import java.io.IOException;
import java.net.BindException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Arrays;

public class Main {
    public static void main(String[] args) throws Exception {
        MyDB myDB = MyDB.getInstance();
        new Thread(() -> {

            TCPClient client;

            try {
                client = new TCPClient(InetAddress.getLocalHost(), Constants.SERVER_PORT);

                Thread clientThread = new Thread(client);
                clientThread.start();

                Thread.sleep(1000);

                UserDao userDao1 = new UserDaoImpl(myDB);
                UserRepository userRepository1 = new UserRepositoryImpl(userDao1);
                UserService userService1 = new UserServiceImpl(userRepository1, client.getSocket());
                UserServicee userServicee1 = new UserServiceeImpl(userRepository1, client.getSocket());
                UserController userController1 = new UserController(userService1, userServicee1);

                HttpServer server1 = HttpServer.create(new InetSocketAddress(8000), 0);
                MyHTTPServer myServer1 = new MyHTTPServer(server1, userController1);

                myServer1.startHttpServer();


                new Thread(() -> {
                    try {
                        userController1.listenServer();
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }).start();



            } catch (Exception e) {
                e.printStackTrace();
            }


        }).start();

        new Thread(() -> {
           TCPClient client2;

            try {
                client2 = new TCPClient(InetAddress.getLocalHost(), Constants.SERVER_PORT);

                Thread clientThread2 = new Thread(client2);
                clientThread2.start();

                Thread.sleep(1000);


                UserDao userDao2 = new UserDaoImpl(myDB);
                UserRepository userRepository2 = new UserRepositoryImpl(userDao2);
                UserService userService2 = new UserServiceImpl(userRepository2, client2.getSocket());
                UserServicee userServicee2 = new UserServiceeImpl(userRepository2, client2.getSocket());
                UserController userController2 = new UserController(userService2, userServicee2);

                HttpServer server2 = HttpServer.create(new InetSocketAddress(8001), 0);
                MyHTTPServer myServer2 = new MyHTTPServer(server2, userController2);

                myServer2.startHttpServer();


                new Thread(() -> {
                    try {
                        userController2.listenServer();
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }).start();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }).start();

        new Thread(() -> {

            TCPClient client3;
            try {
                client3 = new TCPClient(InetAddress.getLocalHost(), Constants.SERVER_PORT);

                Thread clientThread3 = new Thread(client3);
                clientThread3.start();

                Thread.sleep(1000);

                UserDao userDao3 = new UserDaoImpl(myDB);
                UserRepository userRepository3 = new UserRepositoryImpl(userDao3);
                UserService userService3 = new UserServiceImpl(userRepository3, client3.getSocket());
                UserServicee userServicee3 = new UserServiceeImpl(userRepository3, client3.getSocket());
                UserController userController3 = new UserController(userService3, userServicee3);

                HttpServer server3 = HttpServer.create(new InetSocketAddress(8002), 0);
                MyHTTPServer myServer3 = new MyHTTPServer(server3, userController3);

                myServer3.startHttpServer();


                new Thread(() -> {
                    try {
                        userController3.listenServer();
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }).start();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }).start();



        ApplicationManager.getInstance().run();

    /*
        Server server = Server.getInstance(1233);
        byte[] macKey = Authentication.generateMACKey();
        PublicKey serverPublicKey = Confidentiality.getPublicKeyFromByteArray(Confidentiality.getByteArrayFromPublicKey(server.getPublicKey()));
        byte[] encryptedMacKey = Confidentiality.encryptWithPublicKey(macKey, serverPublicKey);
        String macKeyString = "MAC" + " " + "Secretmsg123!" + Arrays.toString(encryptedMacKey);
        // mackey
        System.out.println("MAC key: " + Arrays.toString(macKey));
        System.out.println("Encrypted: " + Arrays.toString(encryptedMacKey));
        System.out.println("MAC generated by client: " + Arrays.toString(Authentication.generateMAC("Secretmsg123!".getBytes(), macKey)));

        byte[] decrypted = Confidentiality.decryptWithPrivateKey(encryptedMacKey, Confidentiality.getPrivateKeyFromByteArray(Confidentiality.getByteArrayFromPrivateKey(server.getKeyPair().getPrivate())));
        System.out.println("Decrypted: " + Arrays.toString(decrypted));
        System.out.println("MAC generated by server: " + Arrays.toString(Authentication.generateMAC("Secretmsg123!".getBytes(), macKey)));


     */

    }
}