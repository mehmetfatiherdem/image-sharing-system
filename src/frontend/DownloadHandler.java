package frontend;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import controller.UserController;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;

public class DownloadHandler implements HttpHandler {

    private UserController userController;

    public DownloadHandler() {

    }

    public DownloadHandler(UserController userController) {
        this.userController = userController;
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        if ("POST".equals(exchange.getRequestMethod())) {

            InputStreamReader isr = new InputStreamReader(exchange.getRequestBody(), "utf-8");
            BufferedReader br = new BufferedReader(isr);
            StringBuilder imageName = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) {
                imageName.append(line);
            }

            System.out.println("Image Name: " + imageName);

            userController.downloadImage(imageName.toString());


        } else {
            // Serve the registration form
            String response = new String(Files.readAllBytes(Paths.get("src/frontend/download.html")));
            exchange.sendResponseHeaders(200, response.length());
            OutputStream os = exchange.getResponseBody();
            os.write(response.getBytes());
            os.close();
        }

    }

    public void setUserController(UserController userController) {
        this.userController = userController;
    }

    public UserController getUserController() {
        return userController;
    }
}
