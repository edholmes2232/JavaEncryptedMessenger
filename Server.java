//package cw1server;

//import shared.Message;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;

public class Server {
	static ObjectOutputStream oos;
	static ObjectInputStream ois;
	static ArrayList<Message> userMessages;
	static ArrayList<Message> msgList;
	
	static void sendMsg(Object ... objs) throws IOException {
		for (Object o: objs) {
			if (o instanceof Character)		oos.writeChar((Character)o);
			else if (o instanceof String)	oos.writeUTF((String)o);
			else if (o instanceof Integer)	oos.writeInt((Integer)o);
			oos.flush();
		}
	}

	static void sendMail(String hash) throws IOException {
		 Integer msgCount = 0;
		 
		 for (Message msg: msgList) {
			 if (msg.recipientHash.contentEquals(hash)) {
				 msgCount++;
				 userMessages.add(msg);
			 }
		 }
		 sendMsg(msgCount);
		 for (Message msg: userMessages) {
			 oos.writeObject(msg); //Objects incoming
			 msgList.remove(msg);
			 oos.flush();
		 }
	}
	
	
	public static void main(String[] args) throws Exception {
		int port = Integer.parseInt(args[0]);
		ServerSocket ss = new ServerSocket(port);
		System.out.println("Waiting for connection...");
		
		msgList = new ArrayList<Message>();

		String userHash = null;
		while (true) {
			char CLIENTCODE = '0';

			try {
				Socket s = ss.accept();
				System.out.println("CLIENT CONNECTED");
				oos = new ObjectOutputStream(s.getOutputStream());
				ois = new ObjectInputStream(s.getInputStream());
				userMessages = new ArrayList<Message>();
				
				do {
					CLIENTCODE = ois.readChar();
					switch(CLIENTCODE) {
					case 'H':
						System.out.println("HASH RECEIVED");
						userHash = ois.readUTF();
						break;
					case 'M':
						System.out.println("SENDING MAIL");
						sendMail(userHash);
						break;
				
					case 'S':
						Message msg = (Message)ois.readObject();
						msgList.add(msg);
						System.out.println("MESSAGE RECIEVED");
						break;
					}
				}while (CLIENTCODE != 'E');
				System.out.println("CLIENT DISCONNECTED\n\n");

			}catch (Exception e) {
				System.err.println(e);
				CLIENTCODE = 'E';
			}
		}
	}

}
