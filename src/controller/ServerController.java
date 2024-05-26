package controller;

import service.ServerService;

import java.net.Socket;

public class ServerController implements Runnable{
    private final ServerService serverService;
    private final Socket socket;
    public ServerController(Socket socket, ServerService serverService) {
        this.socket = socket;
        this.serverService = serverService;
    }

    public void handleRequests() {
        serverService.handleRequests(socket);
    }

    @Override
    public void run() {
        handleRequests();
    }
}
