package helper.format;

import java.util.HashMap;
import java.util.Map;

public class Message {

    // now write formatters and parsers
    /*
        message format:
        {
            "message": "HELLO",
            "data": {
                "username": "username",
                "password": "password",
            }
        }
     */

    public static String formatMessage(String message) {
        StringBuilder formattedMessage = new StringBuilder();
        formattedMessage.append("{\n");
        formattedMessage.append("\t\"message\": \"" + message + "\",\n");
        formattedMessage.append("}\n");
        return formattedMessage.toString();
    }

    public static String formatMessage(String message, String hmac, String[] dataKeys, String[] dataValues) {
        StringBuilder formattedMessage = new StringBuilder();
        formattedMessage.append("{\n");
        formattedMessage.append("\t\"message\": \"" + message + "\",\n");
        formattedMessage.append("\t\"hmac\": \"" + hmac + "\",\n");
        //formattedMessage.append("\t\"data\": {\n");
        for (int i = 0; i < dataKeys.length; i++) {
            formattedMessage.append("\t\t\"" + dataKeys[i] + "\": \"" + dataValues[i] + "\"").append(",\n");

        }
        formattedMessage.append("\t}\n");
        formattedMessage.append("}\n");
        return formattedMessage.toString();
    }

    public static String formatMessage(String message, String[] dataKeys, String[] dataValues) {
        StringBuilder formattedMessage = new StringBuilder();
        formattedMessage.append("{\n");
        formattedMessage.append("\t\"message\": \"" + message + "\",\n");
        //formattedMessage.append("\t\"data\": {\n");
        for (int i = 0; i < dataKeys.length; i++) {
            formattedMessage.append("\t\t\"" + dataKeys[i] + "\": \"" + dataValues[i] + "\"").append(",\n");

        }
        formattedMessage.append("\t}\n");
        formattedMessage.append("}\n");
        return formattedMessage.toString();
    }

    public static Map<String, String> getKeyValuePairs(String message) {

        Map<String, String> result = new HashMap<>();
        int length = message.length();
        StringBuilder key = new StringBuilder();
        StringBuilder value = new StringBuilder();
        boolean parsingKey = true;
        boolean insideQuotes = false;

        for (int i = 0; i < length; i++) {
            char c = message.charAt(i);

            if (c == '"') {
                insideQuotes = !insideQuotes;
                continue;
            }

            if (insideQuotes) {
                if (parsingKey) {
                    key.append(c);
                } else {
                    value.append(c);
                }
                continue;
            }

            if (Character.isWhitespace(c)) {
                continue;
            }

            switch (c) {
                case '{':
                    continue;
                case ':':
                    parsingKey = false;
                    break;
                case ',':
                case '}':
                    if (key.length() > 0 && value.length() > 0) {
                        result.put(key.toString().trim(), value.toString().trim());
                        key.setLength(0);
                        value.setLength(0);
                    }
                    parsingKey = true;
                    break;
                default:
                    if (parsingKey) {
                        key.append(c);
                    } else {
                        value.append(c);
                    }
                    break;
            }
        }

        // Add the last key-value pair if present
        if (key.length() > 0 && value.length() > 0) {
            result.put(key.toString().trim(), value.toString().trim());
        }

        return result;

    }


}
