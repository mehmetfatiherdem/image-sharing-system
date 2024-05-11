import dto.UserDTO;

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

    }
}
