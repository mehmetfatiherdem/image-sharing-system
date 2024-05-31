package frontend;

import com.sun.net.httpserver.HttpServer;
import controller.UserController;
import db.MyDB;
import service.UserService;
import service.UserServicee;

import java.io.IOException;
import java.net.InetSocketAddress;

public class MyHTTPServer {

    private HttpServer server;
    private UserController userController;

    public MyHTTPServer() {

    }

    public MyHTTPServer(HttpServer server, UserController userController) {
        this.server = server;
        this.userController = userController;
    }

    public void startHttpServer() throws IOException {

        MyDB myDB = MyDB.getInstance();
        myDB.connect();

        UploadHandler uploadHandler = new UploadHandler(userController);
        DownloadHandler downloadHandler = new DownloadHandler(userController);

        LoginHandler loginHandler = new LoginHandler(userController);
        RegisterHandler registerHandler = new RegisterHandler(userController);

        server.createContext("/", registerHandler);
        server.createContext("/login", loginHandler);
        server.createContext("/upload", uploadHandler);
        server.createContext("/download", downloadHandler);
        server.setExecutor(null); // creates a default executor
        server.start();

        System.out.println("HTTP Server started on port 8000");

    }
}
