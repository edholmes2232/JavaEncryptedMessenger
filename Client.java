import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.FileInputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.net.Socket;
import java.util.Scanner;
import javax.crypto.BadPaddingException;




class Crypto {
	
	 String getHash(String str) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		 byte[] digest = md.digest(str.getBytes(StandardCharsets.UTF_8));
		 BigInteger num = new BigInteger(1, digest);
		 
		 StringBuilder hexString = new StringBuilder(num.toString(16));
		 return hexString.toString();
	}
	
	SecretKey generateKey() throws Exception {
		KeyGenerator kg = KeyGenerator.getInstance("AES");
		kg.init(256);
		SecretKey key = kg.generateKey();
		return key;
	}
	
	IvParameterSpec generateIv() {
		SecureRandom rand = new SecureRandom();
		byte str[] = new byte[16];
		rand.nextBytes(str);
		IvParameterSpec iv = new IvParameterSpec(str);
		return iv;
	}
		
	
	byte[] encryptMsg(String msg, SecretKey aesKey, IvParameterSpec iv)
                                                        throws Exception {
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
		cipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
		byte[] encryption = cipher.doFinal(msg.getBytes());
		return encryption;
	}
	
	PublicKey getPubKey(String recipient) throws Exception{
		
		ObjectInputStream keyFile = new ObjectInputStream(new FileInputStream(
                        System.getProperty("user.dir")+"/"+recipient+".pub"));
		byte[] encodedKey = ((PublicKey) keyFile.readObject()).getEncoded();
		
		String b64Key = Base64.getEncoder().encodeToString(encodedKey);
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedKey);

		KeyFactory kf = KeyFactory.getInstance("RSA");
		PublicKey pubKey = kf.generatePublic(keySpec);
		keyFile.close();
		return pubKey;
	}
	
	PrivateKey getPrivKey(String userID) throws Exception {
		ObjectInputStream keyFile = new ObjectInputStream(new FileInputStream(
                                System.getProperty("user.dir")+"/"+userID+".prv"));
		byte[] encodedKey = ((PrivateKey) keyFile.readObject()).getEncoded();
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encodedKey);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		PrivateKey privKey = kf.generatePrivate(keySpec);
		keyFile.close();
		return privKey;
	}
	
	byte[] encryptKey(SecretKey aesKey, PublicKey recPubKey) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, recPubKey);
		byte[] encryption = cipher.doFinal(aesKey.getEncoded());
		return encryption;
	}
	
	byte[] generateSig(String hash, Date date, byte[] encKey, 
			IvParameterSpec iv, byte[] encMsg, PrivateKey userPrivKey) throws Exception {
		Signature sig = Signature.getInstance("SHA1withRSA");		
		sig.initSign(userPrivKey);
		
		sig.update(hash.getBytes());
		sig.update(date.toString().getBytes());
		sig.update(encKey);
		sig.update(iv.getIV());
		sig.update(encMsg);
		byte[] data = sig.sign();
		return data;
	}
	
		Boolean verifySig(String hash, Date date, byte[] encKey, byte[] signature,
							byte[] iv, byte[] encMsg, PublicKey senderPubKey) throws Exception {
		Signature sig = Signature.getInstance("SHA1withRSA");
		sig.initVerify(senderPubKey);
		
		sig.update(hash.getBytes());
		sig.update(date.toString().getBytes()); 
		sig.update(encKey);
		sig.update(iv);
		sig.update(encMsg);
		return sig.verify(signature);
	}
	
	SecretKey decryptKey(byte[] encKey, PrivateKey privKey)  throws Exception {
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.DECRYPT_MODE, privKey);
		byte[] data = cipher.doFinal(encKey);
		SecretKey key = new SecretKeySpec(data, 0, data.length, "AES");
		return key;
	}
	
	
	String[] decryptMsg(byte[] msg, SecretKey aesKey, byte[] ivBytes) throws Exception {
		String[] returnMsg = null;
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
		IvParameterSpec iv = new IvParameterSpec(ivBytes);
		cipher.init(Cipher.DECRYPT_MODE, aesKey, iv);
		byte[] decrypt = cipher.doFinal(msg);
		returnMsg = new String(decrypt).split("\n");
		return returnMsg;
	}
}




public class Client {
	static ObjectOutputStream oos;
	static ObjectInputStream ois;
	static ObjectInputStream keyFile;
	
	static Crypto crypto = new Crypto();
	static Scanner sc = new Scanner(System.in);
	
	static String userInput;
	static PrivateKey userPrivKey;
	static PrivateKey encodedPrivKey;
	
    //overloaded method, send control char + any other args to Tx
	static void sendMsg(Object... objs) throws IOException {
		for (Object o: objs) {
			if (o instanceof Character)      oos.writeChar((Character)o);
			else if (o instanceof String)    oos.writeUTF((String)o);
			else if (o instanceof Integer)   oos.writeInt((Integer)o);
			else if (o instanceof Object)    oos.writeObject((Object)o);
			else System.err.println("ERROR TRANSMITTING");
			oos.flush();
		}
	}
	
	static void recMail() throws Exception {
		int msgCount = ois.readInt();		
		System.out.println("You received  "+msgCount+" messages.");
		for (int i = 0; i < msgCount; i++) {
			Message msg = (Message) ois.readObject();
			
			try {
				SecretKey key 			= crypto.decryptKey(msg.key, userPrivKey);
				String[] plainMsg 		= crypto.decryptMsg(msg.encryptedMsg, key, msg.iv);				
				PublicKey senderPubKey 	= crypto.getPubKey(plainMsg[0]);
				
				if (!crypto.verifySig(msg.recipientHash, msg.timestamp, msg.key, 
									msg.signature, msg.iv,msg.encryptedMsg, senderPubKey)) {
					System.err.println("Couldn't verify Signature");
					System.err.flush(); //Flush err before out
				}
				System.out.println("\n"+plainMsg[0]+"'s message:");
				System.out.println(plainMsg[1]);
				System.out.println(msg.timestamp.toString());
			} catch (BadPaddingException e) {
				System.err.println("UNABLE TO DECRYPT MESSAGE");
				System.err.flush();
			}
		}
	}
	

	public static void main(String[] args) throws Exception {
		String host = args[0]; 
		int port = Integer.parseInt(args[1]);
		String userID = args[2];
		String userHash = crypto.getHash(userID);
		System.out.println("Connected to "+host+":"+port);
		try {
			userPrivKey = crypto.getPrivKey(userID);
		} catch (FileNotFoundException e) {
			System.out.println("Public Key not found, ensure keys placed in current working directory:\n" + 
                                                                        System.getProperty("user.dir"));
			System.exit(1);
		}
		String recipient,msg;
		
		Socket s = new Socket(host, port);
		oos = new ObjectOutputStream(s.getOutputStream());
		ois 	= new ObjectInputStream(s.getInputStream());
		
		sendMsg('H', userHash);
		sendMsg('M');
		recMail();
		
		
		System.out.print("\nDo you want to send a message?\n> ");
		userInput = sc.nextLine();
		char SEND = userInput.charAt(0);
		while (SEND == 'y' || SEND == 'Y') { 
			System.out.print("Who to?\n> ");
			recipient = sc.nextLine();
			
			System.out.print("Type your message:\n> ");
			msg = sc.nextLine();
			
			String toEnc = userID+"\n"+msg;
			java.util.Date date = new java.util.Date();

			Message newMsg 	= new Message();
			try {
				PublicKey recPubKey = crypto.getPubKey(recipient);
    
				SecretKey aesKey 	= crypto.generateKey();
				IvParameterSpec iv  = crypto.generateIv();
				byte[] encMsg 		= crypto.encryptMsg(toEnc, aesKey, iv);
				byte[] encKey		= crypto.encryptKey(aesKey, recPubKey);
	
				byte[] sig	= crypto.generateSig(crypto.getHash(recipient), 
															date, 
															encKey, 
															iv, 
															encMsg, 
															userPrivKey);
			
				newMsg.recipientHash	= crypto.getHash(recipient);
				newMsg.encryptedMsg 	= encMsg;
				newMsg.timestamp 		= date;
				newMsg.iv				= iv.getIV();
				newMsg.key				= encKey;
				newMsg.signature		= sig;
					
				sendMsg('S',newMsg);
			} catch (FileNotFoundException e) {
				System.err.println("Public Key not found, ensure keys placed in current working directory:\n"+
														System.getProperty("user.dir"));
			}
			System.out.print("\nDo you want to send a message?\n> ");
			userInput = sc.nextLine();
			SEND = userInput.charAt(0);
		}
		sendMsg('E'); //exit server
		s.close();
	}
}
