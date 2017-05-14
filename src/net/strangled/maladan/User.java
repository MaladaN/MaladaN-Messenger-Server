package net.strangled.maladan;


public class User {
    //Used by the server to keep track of sessions.

    private boolean loggedIn;
    private String base64Username;

    public User(boolean loggedIn, String base64Username) {
        this.loggedIn = loggedIn;
        this.base64Username = base64Username;
    }

    public boolean isLoggedIn() {
        return loggedIn;
    }

    public String getBase64Username() {
        return base64Username;
    }
}
