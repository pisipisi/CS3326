/* Group server. Server loads the users from UserList.bin.
 * If user list does not exists, it creates a new list and makes the user the server administrator.
 * On exit, the server saves the user list to file. 
 */

/*
 * TODO: This file will need to be modified to save state related to
 *       groups that are created in the system
 *
 */

import java.net.ServerSocket;
import java.net.Socket;
import java.io.*;
import java.util.*;
import java.security.*;
import javax.crypto.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;


public class GroupServer extends Server {

	public static final int SERVER_PORT = 8765;
	public UserList userList;
	private KeyPair keys = null;
    
	public GroupServer() {
		super(SERVER_PORT, "ALPHA");
	}
	
	public GroupServer(int _port) {
		super(_port, "ALPHA");
	}
	
	public void start() {
		// Overwrote server.start() because if no user file exists, initial admin account needs to be created
		
		String userFile = "UserList.bin";
		String keyFile = "GSKeyList.bin";
		Scanner console = new Scanner(System.in);
		ObjectInputStream userStream;
		ObjectInputStream groupStream;
		Security.addProvider(new BouncyCastleProvider());
		final int RSAKEYSIZE = 2048;
		
		//This runs a thread that saves the lists on program exit
		Runtime runtime = Runtime.getRuntime();
		runtime.addShutdownHook(new ShutDownListener(this));
		
		// Open or create file with RSA key pairs
		try {
			FileInputStream fis = new FileInputStream(keyFile);
			userStream = new ObjectInputStream(fis);
			keys = (KeyPair)userStream.readObject();
			userStream.close();
			fis.close();
			System.out.println("Loaded keys.");
		}
		catch (FileNotFoundException e) {
			System.out.println("GSKeyList File Does Not Exist. Creating GSKeyList...");
			// create the keys
			try {
				KeyPairGenerator keyGenRSA = KeyPairGenerator.getInstance("RSA", "BC");
				SecureRandom keyGenRandom = new SecureRandom();
				byte bytes[] = new byte[20];
				keyGenRandom.nextBytes(bytes);
				keyGenRSA.initialize(RSAKEYSIZE, keyGenRandom);
				keys = keyGenRSA.generateKeyPair();
				System.out.println("Created keys.");
			}
			catch (Exception ee) {
				System.err.println("Error generating RSA keys.");
				ee.printStackTrace(System.err);
				System.exit(-1);
			}
			// save the keys
			System.out.println("Saving GSKeyList...");
			ObjectOutputStream keyOut;
			try {
				keyOut = new ObjectOutputStream(new FileOutputStream(keyFile));
				keyOut.writeObject(keys);
				keyOut.close();
			}
			catch(Exception ee) {
				System.err.println("Error writing to GSKeyList.");
				ee.printStackTrace(System.err);
				System.exit(-1);
			}
		}
		catch (IOException e) {
			System.out.println("Error reading from GSKeyList file");
			System.exit(-1);
		}
		catch (ClassNotFoundException e) {
			System.out.println("Error reading from GSKeyList file");
			System.exit(-1);
		}
		
		//Open user file to get user list
		try
		{
			FileInputStream fis = new FileInputStream(userFile);
			userStream = new ObjectInputStream(fis);
			userList = (UserList)userStream.readObject();
		}
		catch(FileNotFoundException e)
		{
			System.out.println("UserList File Does Not Exist. Creating UserList...");
			System.out.println("No users currently exist. Your account will be the administrator.");
			System.out.print("Enter your username: ");
			String username = console.next();
			byte pwHash[] = getNewPasswordHash();
			
			//Create a new list, add current user to the ADMIN group. They now own the ADMIN group.
			userList = new UserList();
			userList.addUser(username);
			userList.setUserHash(username, pwHash);
			userList.addGroup(username, "ADMIN");
			userList.addOwnership(username, "ADMIN");
		}
		catch(IOException e)
		{
			System.out.println("Error reading from UserList file");
			System.exit(-1);
		}
		catch(ClassNotFoundException e)
		{
			System.out.println("Error reading from UserList file");
			System.exit(-1);
		}
		
		//Autosave Daemon. Saves lists every 5 minutes
		AutoSave aSave = new AutoSave(this);
		aSave.setDaemon(true);
		aSave.start();
		
		//This block listens for connections and creates threads on new connections
		try
		{
			
			final ServerSocket serverSock = new ServerSocket(port);
			
			Socket sock = null;
			GroupThread thread = null;
			
			while(true)
			{
				sock = serverSock.accept();
				thread = new GroupThread(sock, this, keys.getPrivate());
				thread.start();
			}
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
	
	public PublicKey getServerPublicKey() {
		return keys.getPublic();
	}
	
	public Token getSignedToken(Token aToken) {
		try {
			// Create the token's signature
			Signature tokenSign = Signature.getInstance("SHA1WithRSA", "BC");
			tokenSign.initSign(keys.getPrivate());
			tokenSign.update(aToken.getContents().getBytes());
			aToken.setSignature(tokenSign.sign());
			return aToken;
		}
		catch (Exception e) {
			System.err.println("Signing Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return null;
		}
	}
	
	public byte[] getNewPasswordHash() {
		// Get password
		Console secret = System.console();
		char pwArray1[];
		do {
			pwArray1 = secret.readPassword("Enter a new password: ");
			char pwArray2[] = secret.readPassword("Re-enter the password: ");
			if (Arrays.equals(pwArray1,pwArray2)) {
				if (pwArray1.length >= 3) {
					break;
				}
				else {
					System.out.println("Password must be at least three characters long. Please try again");
				}
			}
			else {
				System.out.println("Passwords did not match. Please try again");
			}
		} while (true);
		// Do the hash and return it
		return getHash(pwArray1);
	}

	public byte[] getHash(char[] input) {
		byte doHash[] = null;
		try { // to create array of bytes from input
			doHash = new String(input).getBytes("UTF8");
		}
		catch (UnsupportedEncodingException e) {
			e.printStackTrace(System.err);
			return null;
		}
		try { // to get hash of byte array
			MessageDigest messageDigest = MessageDigest.getInstance("SHA1", "BC");
			messageDigest.update(doHash);
			return messageDigest.digest();
		}
		catch (Exception e) {
			e.printStackTrace(System.err);
			return null;
		}
	}

	public boolean comparePasswordHash(String username, char[] password) {
		// Prepare to do the hash
		byte pwHash[] = null;
		try { // to create array of bytes from input
			pwHash = new String(password).getBytes("UTF8");
		}
		catch (UnsupportedEncodingException e) {
			e.printStackTrace(System.err);
			return false;
		}
		try { // to get hash of byte array
			MessageDigest messageDigest = MessageDigest.getInstance("SHA1", "BC");
			messageDigest.update(pwHash);
			if (Arrays.equals(messageDigest.digest(), userList.getUserHash(username))) {
				return true;
			}
			else {
				return false;
			}
		}
		catch (Exception e) {
			e.printStackTrace(System.err);
			return false;
		}
	}
}

//This thread saves the user list
class ShutDownListener extends Thread
{
	public GroupServer my_gs;
	
	public ShutDownListener (GroupServer _gs) {
		my_gs = _gs;
	}
	
	public void run()
	{
		System.out.println("Shutting down server");
		ObjectOutputStream outStream;
		try
		{
			outStream = new ObjectOutputStream(new FileOutputStream("UserList.bin"));
			outStream.writeObject(my_gs.userList);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
}

class AutoSave extends Thread
{
	public GroupServer my_gs;
	
	public AutoSave (GroupServer _gs) {
		my_gs = _gs;
	}
	
	public void run()
	{
		do
		{
			try
			{
				Thread.sleep(300000); //Save group and user lists every 5 minutes
				System.out.println("Autosave group and user lists...");
				ObjectOutputStream outStream;
				try
				{
					outStream = new ObjectOutputStream(new FileOutputStream("UserList.bin"));
					outStream.writeObject(my_gs.userList);
				}
				catch(Exception e)
				{
					System.err.println("Error: " + e.getMessage());
					e.printStackTrace(System.err);
				}
			}
			catch(Exception e)
			{
				System.out.println("Autosave Interrupted");
			}
		}while(true);
	}
}
