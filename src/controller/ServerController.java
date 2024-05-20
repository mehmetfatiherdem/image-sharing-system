package controller;

import service.ServerService;

public class ServerController {
    private final ServerService serverService;
    public ServerController(ServerService serverService) {
        this.serverService = serverService;
    }

    public void handleRequests() {
        serverService.handleRequests();
    }

}
