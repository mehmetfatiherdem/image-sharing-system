package frontend;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import controller.UserController;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;

public class RegisterHandler implements HttpHandler {

    private UserController userController;

    public RegisterHandler() {

    }

    public RegisterHandler(UserController userController) {
        this.userController = userController;
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


            userController.register(username, password);


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
}
