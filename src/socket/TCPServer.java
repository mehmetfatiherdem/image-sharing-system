package socket;

import java.net.ServerSocket;

public class TCPServer implements Runnable{
    private final int port;
    private ServerSocket socket;

    public TCPServer(int port) {
        this.port = port;
    }

    @Override
    public void run() {
        while (true) {
            try {
                socket = new ServerSocket(port);
                socket.accept();

            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    // Getters
    public int getPort() {
        return port;
    }

    public ServerSocket getSocket() {
        return socket;
    }
}
