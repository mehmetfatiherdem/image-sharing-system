package frontend;

import com.sun.net.httpserver.HttpServer;
import db.MyDB;

import java.io.IOException;
import java.net.InetSocketAddress;

public class MyHTTPServer {
    public static void startHttpServer() throws IOException {

        MyDB myDB = MyDB.getInstance();
        myDB.connect();

        UploadHandler uploadHandler = new UploadHandler();
        DownloadHandler downloadHandler = new DownloadHandler();

        LoginHandler loginHandler = new LoginHandler(uploadHandler, downloadHandler);
        RegisterHandler registerHandler = new RegisterHandler(loginHandler, myDB);

        HttpServer server = HttpServer.create(new InetSocketAddress(8000), 0);
        server.createContext("/", registerHandler);
        server.createContext("/login", loginHandler);
        server.createContext("/upload", uploadHandler);
        server.createContext("/download", downloadHandler);
        server.setExecutor(null); // creates a default executor
        server.start();

        System.out.println("HTTP Server started on port 8000");

    }
}
