package pcsClient;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.net.ConnectException;
import java.net.UnknownHostException;

public class Client {
    private Socket server;
    private PrintWriter outputWriter;
    private BufferedReader inputBuffer;
    private String username;
    
    public boolean login(String user, String pass) {
        boolean accepted = false;
        
        outputWriter.println("LOGIN: " + user + "," + pass);
        outputWriter.flush();
        String response;
        try {
            response = inputBuffer.readLine();
            if(response.equals("ACCEPTED")) {
                accepted = true;
                username = user;
            }
        } catch(IOException e) {
            System.out.println(e);
            e.printStackTrace();
        }
        
        return accepted;
    }
    
    public void connect(String ip, short port) throws ConnectException, UnknownHostException, IOException {
        server = new Socket(ip, port);
        try {
            
            inputBuffer = new BufferedReader(new InputStreamReader(server.getInputStream()));
            outputWriter = new PrintWriter(server.getOutputStream());
        } catch (IOException e) {
            System.out.println(e);
            e.printStackTrace();
        }    
    }
    
    public boolean disconnect() {
        try {
            server.close();
            inputBuffer.close();
        } catch(IOException e) {
            System.out.println(e);
            e.printStackTrace();
            return false;
        }
        outputWriter.close();
        return true;
    }
    
    public void write(String msg) {
        outputWriter.println(msg);
        outputWriter.flush();
    }
    
    public String read() {
        String line = null;
        try {
            line = inputBuffer.readLine();
        } catch(IOException e) {
            System.out.println(e);
            e.printStackTrace();
        }
        return line;
    }
    
    public void sendChatMessage(String msg) {
        write(username + ": " + msg);
    }
    
    public void sendQuitMessage() {
        write("QUIT");
    }
    
}
