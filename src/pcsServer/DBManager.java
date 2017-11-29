package pcsServer;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Arrays;
import java.util.Base64;

public class DBManager {
	private Connection db;
	private String url;
	private String username;
	private String password;
	
	private final static int ITERATION_NUMBER = 1000;
	
	public DBManager(String host, String user, String pass) {
		url = host;
	    username = user;
	    password = pass;

        try {
            db = DriverManager.getConnection(url, username, password);
        } catch (SQLException e) {
        	System.err.println(e);
            e.printStackTrace();
        }
	}

   public boolean authenticate(String username, String password) throws SQLException, NoSuchAlgorithmException
   {
       PreparedStatement ps = null;
       ResultSet rs = null;
       try {
           boolean userExist = true;
           if (username == null || password == null) {
               userExist = false;
               username = "";
               password = "";
           }
 
           ps = db.prepareStatement("SELECT PASSWORD, SALT FROM CREDENTIAL WHERE LOGIN = ?");
           ps.setString(1, username);
           rs = ps.executeQuery();
           String digest, salt;
           if (rs.next()) {
               digest = rs.getString("PASSWORD");
               salt = rs.getString("SALT");
              
               if (digest == null || salt == null) {
                   throw new SQLException("Database Error");
               }
               if (rs.next()) { 
                   throw new SQLException("Database Error");
               }
           } else {
               digest = "000000000000000000000000000=";
               salt = "00000000000=";
               userExist = false;
           }
 
           byte[] bDigest = base64ToByte(digest);
           byte[] bSalt = base64ToByte(salt);
 
           byte[] proposedDigest = getHash(ITERATION_NUMBER, password, bSalt);
           
           return Arrays.equals(proposedDigest, bDigest) && userExist;
       } catch (IOException ex){
           throw new SQLException("Database  Error");
       }
       finally{
           close(rs);
           close(ps);
       }
   }
 
   
   public boolean userExists(String username) {
	   boolean exists = false;
	   
	   PreparedStatement ps = null;
	   ResultSet rs = null;
	   
	   try {
	       ps = db.prepareStatement("SELECT 1 FROM CREDENTIAL WHERE LOGIN='" + username + "' LIMIT 1");
	       rs = ps.executeQuery();
	       if (rs.next()) exists = true;
	   } catch (SQLException e) {
		   System.err.println(e);
		   e.printStackTrace();
	   }
	   
	   return exists;
   }
   
   public boolean createUser(String username, String password) throws SQLException, NoSuchAlgorithmException
   {	   
       PreparedStatement ps = null;
       try {
           if (username != null && password != null && username.length() <= 100) {
        	                 
               SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
               
               byte[] bSalt = new byte[8];
               random.nextBytes(bSalt);
               
               byte[] bDigest = getHash(ITERATION_NUMBER, password, bSalt);
               String sDigest = byteToBase64(bDigest);
               String sSalt = byteToBase64(bSalt);
               
               ps = db.prepareStatement("INSERT INTO CREDENTIAL (LOGIN, PASSWORD, SALT) VALUES (?,?,?)");
               ps.setString(1,username);
               ps.setString(2,sDigest);
               ps.setString(3,sSalt);
               ps.executeUpdate();
               return true;
           } else {
               return false;
           }
       } finally {
           close(ps);
       }
   }
   
   public byte[] getHash(int iterationNb, String password, byte[] salt) throws NoSuchAlgorithmException {
       MessageDigest digest = MessageDigest.getInstance("SHA-1");
       digest.reset();
       digest.update(salt);
       byte[] input = null;
       
       try {
           input = digest.digest(password.getBytes("UTF-8"));
       } catch (UnsupportedEncodingException e) {
    	   System.err.println(e);
    	   e.printStackTrace();
       }
		
       for (int i = 0; i < iterationNb; i++) {
           digest.reset();
           input = digest.digest(input);
       }
       return input;
   }
 
   public void close(Statement ps) {
       if (ps!=null){
           try {
               ps.close();
           } catch (SQLException ignore) {
           }
       }
   }
 
   public void close(ResultSet rs) {
       if (rs!=null){
           try {
               rs.close();
           } catch (SQLException ignore) {
           }
       }
   }
 
   public static byte[] base64ToByte(String data) throws IOException {
       return Base64.getDecoder().decode(data);
   }
 
   public static String byteToBase64(byte[] data){
       return Base64.getEncoder().encodeToString(data);
   }
}

