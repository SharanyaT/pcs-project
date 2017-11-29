package pcsServer;

import java.net.*;
import java.util.ArrayList;
import java.io.IOException;


public class Server {
		
	private ServerSocket listener;
	
	//for now only use 2 clients since the chat works by broadcasting messages
	private ArrayList<Session> clientList; 

	private DBManager db;
	
	Server(short port) {
		try {
			listener = new ServerSocket(port);
			clientList  = new ArrayList<Session>();
		} catch(IOException e) {
			System.err.println(e);
			e.printStackTrace();
		}
	}

	public void run() throws IOException {
		
		String dbUser = "root";
		String dbPass = "snickerdoodle";

		String dbAddress = "jdbc:mysql://localhost:3306/chatdb";
		db = new DBManager(dbAddress, dbUser, dbPass);		
		
		while (true) {
			Socket client = listener.accept();				
			new Thread(new ClientHandler(client, clientList, db)).start();
		}
	}
	
	public static void main(String args[]) {
		
		final short PORT = 1337;
		Server server = new Server(PORT);
		
		try {
			server.run();
		} catch (IOException e) {
			System.err.print(e);
			e.printStackTrace();
		}
	}
	
}

class ClientHandler implements Runnable {
	private Session client;
	
	private ArrayList<Session> clientList;
	
	private DBManager db;
	
	ClientHandler(Socket socket, ArrayList<Session> cl, DBManager database) {
		client = new Session(socket);
		this.clientList = cl;
		db = database;
	}
	
	public void run() {
		String clientMsg = null;
		boolean accepted = false;
		
		do {
			clientMsg = client.read();
			if (clientMsg.equals("QUIT")) {
				client.disconnect();
				return;
			}
			else if (clientMsg.startsWith("NEWUSER: ")) {
				createUser(clientMsg);
			}
			else if (clientMsg.startsWith("LOGIN: ")) {
				accepted = authenticate(clientMsg);
			}
			else
			{
				client.disconnect();
				return;
			}
		} while(!accepted);
		
		while (true) {
			String line = client.read();
			if (line == null) break;
			else {
				broadcast(line);
			}
		}
		
		exit();
	}
	
	private synchronized void createUser(String clientMsg) {
		
		clientMsg = clientMsg.split(" ")[1];
		String username = clientMsg.split(",")[0];
		String password = clientMsg.split(",")[1];
		
		try {
			if (db.userExists(username)) {
				client.write("TAKEN");
			}
			else {
				db.createUser(username, password);			
				client.write("USERCREATED");
			}
		} catch (Exception e) {
			System.err.println(e);
			e.printStackTrace();
		}
	}
	
	private synchronized boolean authenticate(String clientMsg) {
		boolean accepted = false;
		
		clientMsg = clientMsg.split(" ")[1];
		String username = clientMsg.split(",")[0];
		String password = clientMsg.split(",")[1];
		
		try {
			if (db.authenticate(username, password)) {
				accepted = true;
				
	            client.setUsername(username);
	            client.write("ACCEPTED");
	            clientList.add(client);

	    		updateClientUserList();
	    		
	            broadcast(client.getUsername() + " has joined the chat.");
			}
			else client.write("DENIED");
			
		} catch (Exception e) {
			System.err.println(e);
			e.printStackTrace();
		}
		
		return accepted;
	}
	
	private synchronized void exit() {
		String exitMsg = client.getUsername() +" has left the chat.";
		
		broadcast(exitMsg);

		client.disconnect();
		clientList.remove(client);
		updateClientUserList();
	}

	private synchronized void broadcast(String message) 
	{
		//String toUsername = message.split(":")[0];
        for (int i = 0; i < clientList.size(); i++) 
        {
        	//if(clientList.get(i).getUsername().equals(toUsername))
        		clientList.get(i).write(message);
        }
	}
	
	private synchronized void updateClientUserList() {
            String userList = "USERLIST:";
            for (int i = 0; i < clientList.size(); i++) {
            	userList += " " + clientList.get(i).getUsername();
            }
            broadcast(userList);
	}
}