package frontend;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import controller.UserController;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class UploadHandler implements HttpHandler {

    private UserController userController;

    public UploadHandler() {

    }

    public UploadHandler(UserController userController) {
        this.userController = userController;
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        if ("POST".equals(exchange.getRequestMethod())) {

            // Ensure the request is multipart/form-data
            String contentType = exchange.getRequestHeaders().getFirst("Content-Type");
            if (contentType == null || !contentType.startsWith("multipart/form-data")) {
                sendResponse(exchange, "Invalid content type", 400);
                return;
            }

            // Read the request body
            InputStream inputStream = exchange.getRequestBody();
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            byte[] buffer = new byte[2048];
            int length;
            while ((length = inputStream.read(buffer)) != -1) {
                byteArrayOutputStream.write(buffer, 0, length);
            }
            String requestBody = byteArrayOutputStream.toString();

            // Parse the multipart data
            List<String> accessList = new ArrayList<>();
            String imageName = "";
            String[] parts = requestBody.split("--" + contentType.split("=")[1]); // Split by boundary
            for (String part : parts) {
                if (part.contains("name=\"textInput\"")) {
                    // Process text input
                    accessList.addAll(Arrays.asList(extractValue(part).split("\\s+")));
                } else if (part.contains("name=\"imageInput\"")) {
                    // Process image file
                    imageName = extractFilename(part);
                }
            }


            userController.postImage(imageName, "src/assets/" + imageName, accessList);


        } else {
            // Serve the registration form
            String response = new String(Files.readAllBytes(Paths.get("src/frontend/upload.html")));
            exchange.sendResponseHeaders(200, response.length());
            OutputStream os = exchange.getResponseBody();
            os.write(response.getBytes());
            os.close();
        }

    }

    private void sendResponse(HttpExchange exchange, String response, int statusCode) throws IOException {
        exchange.sendResponseHeaders(statusCode, response.getBytes().length);
        OutputStream os = exchange.getResponseBody();
        os.write(response.getBytes());
        os.close();
    }

    private String extractValue(String part) {
        // Extract the actual value from part
        return part.substring(part.indexOf("\r\n\r\n") + 4, part.lastIndexOf("\r\n")).trim();
    }

    private String extractFilename(String part) {
        // Extract filename from Content-Disposition
        String disposition = Arrays.stream(part.split("\r\n"))
                .filter(line -> line.contains("Content-Disposition"))
                .findFirst().orElse("");
        String filename = disposition.replaceFirst("(?i)^.*filename=\"([^\"]+)\".*$", "$1");
        return filename;
    }

    public void setUserController(UserController userController) {
        this.userController = userController;
    }

    public UserController getUserController() {
        return userController;
    }
}

