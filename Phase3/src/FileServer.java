/* FileServer loads files from FileList.bin.  Stores files in shared_files directory. */

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class FileServer extends Server {
	public static final int SERVER_PORT = 4321;
	public static FileList fileList;
	public static String gsAddress;
	public static int gsPort;
	public static PublicKey gsPublicKey;
	private KeyPair keys = null;
	
	public FileServer() {
		super(SERVER_PORT, "FilePile");
	}

	public FileServer(int _port) {
		super(_port, "FilePile");
	}

	public FileServer(int _port, String _gsAddress, int _gsPort) {
		super(_port, "FilePile");
		gsAddress = _gsAddress;
		gsPort = _gsPort;
	}

	public void start() {
		String fileFile = "FileList.bin";
		String keyFile = "FS" + port + "KeyList.bin";
		ObjectInputStream fileStream;
		Security.addProvider(new BouncyCastleProvider());
		final int RSAKEYSIZE = 2048;
		
		//This runs a thread that saves the lists on program exit
		Runtime runtime = Runtime.getRuntime();
		Thread catchExit = new Thread(new ShutDownListenerFS());
		runtime.addShutdownHook(catchExit);
		
		//Open user file to get user list
		try
		{
			FileInputStream fis = new FileInputStream(fileFile);
			fileStream = new ObjectInputStream(fis);
			fileList = (FileList)fileStream.readObject();
		}
		catch(FileNotFoundException e)
		{
			System.out.println("FileList Does Not Exist. Creating FileList...");
			
			fileList = new FileList();
			
		}
		catch(IOException e)
		{
			System.out.println("Error reading from FileList file");
			System.exit(-1);
		}
		catch(ClassNotFoundException e)
		{
			System.out.println("Error reading from FileList file");
			System.exit(-1);
		}
		
		File file = new File("shared_files");
		if (file.mkdir()) {
			System.out.println("Created new shared_files directory");
		}
		else if (file.exists()){
			System.out.println("Found shared_files directory");
		}
		else {
			System.out.println("Error creating shared_files directory");				 
		}

		// Open or create file with RSA key pairs
		try {
			FileInputStream fis = new FileInputStream(keyFile);
			fileStream = new ObjectInputStream(fis);
			keys = (KeyPair)fileStream.readObject();
			fileStream.close();
			fis.close();
			System.out.println("Loaded keys.");
		}
		catch (FileNotFoundException e) {
			System.out.println(keyFile + " File Does Not Exist. Creating " + keyFile + "...");
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
			System.out.println("Saving " + keyFile + "...");
			ObjectOutputStream keyOut;
			try {
				keyOut = new ObjectOutputStream(new FileOutputStream(keyFile));
				keyOut.writeObject(keys);
				keyOut.close();
			}
			catch(Exception ee) {
				System.err.println("Error writing to " + keyFile + ".");
				ee.printStackTrace(System.err);
				System.exit(-1);
			}
		}
		catch (IOException e) {
			System.out.println("Error reading from " + keyFile + " file");
			System.exit(-1);
		}
		catch (ClassNotFoundException e) {
			System.out.println("Error reading from " + keyFile + " file");
			System.exit(-1);
		}

		// Call Group Server and get its Public Key
		GroupClient gc = new GroupClient();
		gc.connect(gsAddress, gsPort);
		if (gc.isConnected()) // check that server is running
		{
			gsPublicKey = gc.getPubKey();
			if (gsPublicKey == null) { // no key retrieved
				System.out.println("Error: Group Server key not retrieved.");
				gc.disconnect();
				System.exit(-1);
			}
			System.out.println("Group Server Public Key retrieved.");
			gc.disconnect();
		}
		else {
			System.out.println("Error - Group Server not reached at given address.");
		}
		
		//Autosave Daemon. Saves lists every 5 minutes
		AutoSaveFS aSave = new AutoSaveFS();
		aSave.setDaemon(true);
		aSave.start();
		
		boolean running = true;
		
		try
		{			
			final ServerSocket serverSock = new ServerSocket(port);
			System.out.printf("%s up and running\n", this.getClass().getName());
			
			Socket sock = null;
			Thread thread = null;
			
			while(running)
			{
				sock = serverSock.accept();
				thread = new FileThread(sock, this, keys.getPrivate(), gsPublicKey);
				thread.start();
			}
			
			System.out.printf("%s shut down\n", this.getClass().getName());
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
}

//This thread saves user and group lists
class ShutDownListenerFS implements Runnable
{
	public void run()
	{
		System.out.println("Shutting down server");
		ObjectOutputStream outStream;

		try
		{
			outStream = new ObjectOutputStream(new FileOutputStream("FileList.bin"));
			outStream.writeObject(FileServer.fileList);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
}

class AutoSaveFS extends Thread
{
	public void run()
	{
		do
		{
			try
			{
				Thread.sleep(300000); //Save group and user lists every 5 minutes
				System.out.println("Autosave file list...");
				ObjectOutputStream outStream;
				try
				{
					outStream = new ObjectOutputStream(new FileOutputStream("FileList.bin"));
					outStream.writeObject(FileServer.fileList);
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
