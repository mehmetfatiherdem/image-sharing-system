package service;

import dto.LoginDTO;
import helper.security.Authentication;
import model.User;
import repository.UserRepository;

import java.io.DataOutputStream;
import java.net.Socket;
import java.util.Arrays;

public class AuthServiceImpl implements AuthService {

    private final UserRepository userRepository;
    private final Socket socket;

    public AuthServiceImpl(UserRepository userRepository, Socket socket) {
        this.userRepository = userRepository;
        this.socket = socket;
    }

    @Override
    public void login(String username, String password) {

        try {
            var user = userRepository.getUser(username);
            byte[] passwordHash = Authentication.hashPassword(password, user.getPasswordSalt());
            LoginDTO loginDTO = new LoginDTO(username, passwordHash);
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());

            String nonce = Authentication.generateNonce();

            var signedMessage = Authentication.sign(nonce.getBytes(), userRepository.getPrivateKey(username));

            String loginMessagePayload = "LOGIN" + " " + loginDTO.getLoginString() + " "
                    + Arrays.toString(signedMessage);

            //String loginMessage = Authentication.appendMACToMessage();

            //out.writeUTF(loginMessage);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public void register(String username, String password) {
        try {
            User user = new User(username, password);


        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public void logout() {

    }
}
