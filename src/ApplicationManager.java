import dto.UserDTO;
import helper.Constants;
import model.Server;
import socket.TCPServer;

import java.util.ArrayList;

public class ApplicationManager {
    private static ApplicationManager instance;
    private final ArrayList<UserDTO> users = new ArrayList<>();

    private ApplicationManager() {
    }

    public static ApplicationManager getInstance() {
        if (instance == null) {
            instance = new ApplicationManager();
        }
        return instance;
    }

    public void run() {
        Server server;

        try {
            server = Server.getInstance();
        } catch (Exception e) {
            e.printStackTrace();
            return;
        }

        server.run();

    }
}
