package frontend;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import controller.UserController;
import dao.UserDao;
import dao.UserDaoImpl;
import db.MyDB;
import helper.Constants;
import repository.UserRepository;
import repository.UserRepositoryImpl;
import service.UserService;
import service.UserServiceImpl;
import service.UserServicee;
import service.UserServiceeImpl;
import socket.TCPClient;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.Paths;

public class RegisterHandler implements HttpHandler {

    private LoginHandler loginHandler;
    private MyDB myDB;

    public RegisterHandler() {

    }

    public RegisterHandler(LoginHandler loginHandler, MyDB myDB) {
        this.loginHandler = loginHandler;
        this.myDB = myDB;
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        if ("POST".equals(exchange.getRequestMethod())) {
            // Read the form data
            InputStreamReader isr = new InputStreamReader(exchange.getRequestBody(), "utf-8");
            BufferedReader br = new BufferedReader(isr);
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) {
                sb.append(line);
            }

            String[] postData = sb.toString().split("&");
            String username = postData[0].split("=")[1];
            String password = postData[1].split("=")[1];

            System.out.println("Username: " + username);
            System.out.println("Password: " + password);

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

                userController.registerr(username, password);

                loginHandler.setUserController(userController);
            } catch (Exception e) {
                e.printStackTrace();
            }


            // Redirect to login page
            exchange.getResponseHeaders().set("Location", "/login");
            exchange.sendResponseHeaders(302, -1);

        } else {
            // Serve the registration form
            String response = new String(Files.readAllBytes(Paths.get("src/frontend/register.html")));
            exchange.sendResponseHeaders(200, response.length());
            OutputStream os = exchange.getResponseBody();
            os.write(response.getBytes());
            os.close();
        }

    }

    public void setLoginHandler(LoginHandler loginHandler) {
        this.loginHandler = loginHandler;
    }

    public LoginHandler getLoginHandler() {
        return loginHandler;
    }
}
