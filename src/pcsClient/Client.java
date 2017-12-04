package pcsClient;

import encryption.EncryptionHandler;
import encryption.OneTimeKeyQueue;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.net.ConnectException;
import java.net.UnknownHostException;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;

public class Client {
    private Socket server;
    private PrintWriter outputWriter;
    private BufferedReader inputBuffer;
    private String username;
    private KeyPair identityKeyPair;
    private KeyPair signedPreKey;
    private OneTimeKeyQueue oneTimeKeyQueue;
    
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
        identityKeyPair = EncryptionHandler.generateECKeys();
        signedPreKey = EncryptionHandler.generateECKeys();
        oneTimeKeyQueue = new OneTimeKeyQueue();
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
        try{
            String encrypted = EncryptionHandler.encryptString(null, msg);
        } catch (Exception e){
            System.out.println("An exception occurred.");
            e.printStackTrace();
            return;
        }
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


    private List<byte[]> requestPublicKeys(){
        List<byte[]> keys = new ArrayList<>();
        //request public Identity, Signed, and One Time keys for recipient from server
        return keys;
    }

    private byte[] generateMasterSecret(){
        /*Generate the following secret:
            ECDH(Iinitiator, Srecipient) || ECDH(Einitiator, Irecipient) ||
            ECDH(Einitiator, Srecipient) || ECDH(Einitiator, Orecipient)
        */


        return null;
    }
}
