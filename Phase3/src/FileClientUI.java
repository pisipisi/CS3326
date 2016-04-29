import java.util.Scanner; // Scanner class required for user input
import java.util.List;
import java.io.*;
import java.security.*;

public class FileClientUI {
	FileClient fc = new FileClient();
	
	public boolean launchUI(UserToken token, String serverAddress, int portNumber) {
		if (fc.connect(serverAddress, portNumber)) {
			Scanner console = new Scanner(System.in); // Scanner object for input
			String userName = token.getSubject();
			int menuChoice = 0;
			boolean exitKey = false;
			final int MAXUSERLENGTH = 32;
			final int MAXGROUPLENGTH = 32;
			final int MAXPATHLENGTH = 256;
			List<String> aList;
			String groupName;
			String currentGroup = new String();
			String userPrompt;
			String sourceFileName;
			String destFileName;
			String fsFile = "FileServerList.bin";
			ObjectInputStream ois;
			PublicKey thisFSKey = fc.getPubKey();
			FileServerID thisFS = new FileServerID(serverAddress, portNumber, thisFSKey);

			// determine whether or not this server has been used before
			try {
				FileInputStream fis = new FileInputStream(fsFile);
				ois = new ObjectInputStream(fis);
				FileServerList fsList = (FileServerList)ois.readObject();
				ois.close();
				fis.close();
				
				if (fsList.hasServer(thisFS)) {
					// We're cool
					System.out.println("File Server's ID is on file. Connection successful.");
				}
				else { // Notify user of unknown File Server
					
					System.out.println("This File Server's identity has not been recorded previously...");
					System.out.println("Address: " + serverAddress);
					System.out.println("Port: " + portNumber);
					System.out.println("Public Key (hex): " + toHexString(thisFSKey.getEncoded()) + "\n");
					
					// Prompt user if would like to add to FileServerList
					System.out.println("Would you like to add this server to your trusted server list? (y/n)");
					String answer = getNonEmptyString("> ", 32);
					if (answer.charAt(0) == 'y' || answer.charAt(0) == 'Y') {
						FileOutputStream fos;
						ObjectOutputStream oos;
						try {
							FileServerList fsl = new FileServerList();
							fsl.addServer(thisFS);
							fos = new FileOutputStream(fsFile);
							oos = new ObjectOutputStream(fos);
							oos.writeObject(fsl);
							oos.close();
							fos.close();
							System.out.println("File Server added to trusted server list.");
						}
						catch(Exception ee) {
							System.err.println("Error writing to " + fsFile + ".");
							ee.printStackTrace(System.err);
							System.exit(-1);
						}
					}
					else {
						System.out.println("Server will not be added. Exiting.");
						exitKey = true;
					}
				}
			}
			catch(FileNotFoundException e) {
				System.out.println("File Server List Does Not Exist. Creating " + fsFile + "...");
				FileOutputStream fos;
				ObjectOutputStream oos;
				try {
					FileServerList fsl = new FileServerList();
					fsl.addServer(thisFS);
					fos = new FileOutputStream(fsFile);
					oos = new ObjectOutputStream(fos);
					oos.writeObject(fsl);
					oos.close();
					fos.close();
				}
				catch(Exception ee) {
					System.err.println("Error writing to " + fsFile + ".");
					ee.printStackTrace(System.err);
					System.exit(-1);
				}
			}
			catch(IOException e) {
				System.out.println("Error reading from " + fsFile);
				System.exit(-1);
			}
			catch(ClassNotFoundException e) {
				System.out.println("Error reading from UserList file");
				System.exit(-1);
			}
			
			// get session key
			if (fc.getSessionKey()) {
				System.out.println("Session key obtained. Connection to server encrypted.");
			}
			else {
				System.out.println("Error while obtaining session key. Exiting.");
				exitKey = true;
			}
			
			while (!exitKey) {
				if (currentGroup.length() > 0) {
					userPrompt = userName + "/" + currentGroup;
				}
				else {
					userPrompt = userName;
				}
				System.out.print("Enter 1 to list the groups you belong to,\n" +
								 "enter 2 to change the current group to traverse,\n" +
								 "enter 3 to list files,\n" +
								 "enter 4 to upload a file to the File Server,\n" +
								 "enter 5 to download a file from the File Server,\n" +
								 "enter 6 to delete a file from the File Server,\n" +
								 "enter 0 to disconnect from File Server...\n" +
								 userPrompt + "> ");
				String inputString = console.nextLine();
				
				try {
					menuChoice = Integer.parseInt(inputString);
				}
				catch(Exception e) {
					menuChoice = -1;
				}
				
				switch (menuChoice) {
					case 1:
						aList = fc.listGroups(token);
						if (aList != null) {
							for (String s: aList) {
								System.out.println(s);
							}
						}
						else {
							System.out.println("Error - user has no groups. Please add groups in Group Server.");
						}
						break;
					case 2:
						groupName = getNonEmptyString("Enter the group name to change to...\n> ", MAXGROUPLENGTH);
						aList = fc.changeGroup(groupName, token);
						if (aList != null) {
							for (String s: aList) {
								System.out.println("Changed to group " + s + ".");
								currentGroup = s;
							}
						}
						else {
							System.out.println("Error - please add groups to Group Server.");
						}
						break;
					case 3:
						aList = fc.listFiles(token);
						if (aList != null && aList.size() != 0) {
							for (String s: aList) {
								System.out.println(s);
							}
						}
						else {
							System.out.println("No files present.");
						}
						break;
					case 4:
						if (currentGroup.length() > 0) {
							sourceFileName = getNonEmptyString("Enter source file path...\n> ", MAXPATHLENGTH);
							destFileName = getNonEmptyString("Enter destination file path...\n> ", MAXPATHLENGTH);
							if (fc.upload(sourceFileName, destFileName, currentGroup, token)) {
								System.out.println(destFileName + " successfully uploaded to group " + currentGroup + ".");
							}
							else {
								System.out.println("Error uploading " + destFileName + " to File Server.");
							}
						}
						else {
							System.out.println("You must pick a group for your workspace (option 2).");
						}
						break;
					case 5:
						if (currentGroup.length() > 0) {
							sourceFileName = getNonEmptyString("Enter source file path...\n> ", MAXPATHLENGTH);
							destFileName = getNonEmptyString("Enter destination file path...\n> ", MAXPATHLENGTH);
							if (fc.download(sourceFileName, destFileName, currentGroup, token)) {
								System.out.println(destFileName + " successfully downloaded.");
							}
						}
						else {
							System.out.println("You must pick a group for your workspace (option 2).");
						}
						break;
					case 6:
						if (currentGroup.length() > 0) {
							sourceFileName = getNonEmptyString("Enter filename to delete...\n> ", MAXPATHLENGTH);
							if (fc.delete(sourceFileName, currentGroup, token)) {
								System.out.println(sourceFileName + " successfully deleted.");
							}
						}
						else {
							System.out.println("You must pick a group for your workspace (option 2).");
						}
						break;
					case 0:
						System.out.println("Disconnecting from File Server...");
						fc.disconnect();
						exitKey = true;
						break;
					default:
						System.out.println("Unknown command. Please try again.");
						break;
				}
			}
			
			return true;
		}
		else { // error connecting
			System.out.println("Error connecting to File Server at " +
							   serverAddress + " port " + portNumber + ".");
			return false;
		}
	}
	
	public static String getNonEmptyString(String prompt, int maxLength) {
		String str = "";
		Scanner scan = new Scanner(System.in);
		
		System.out.print(prompt);        
		
		while (str.length() == 0) {
			str = scan.nextLine();
			
			if (str.length() == 0) {
				System.out.print(prompt);
			}
			else if (str.length() > maxLength) {
				System.out.println("Maximum length allowed is " + maxLength + " characters. Please re-enter.");
				System.out.print(prompt);
				str = "";
			}
		}
		
		return str;
	}
	
	// The following methods are from Oracle:
	// http://docs.oracle.com/cd/E17409_01/javase/6/docs/technotes/guides/security/crypto/CryptoSpec.html#Examples
	
	/*
     * Converts a byte to hex digit and writes to the supplied buffer
     */
    private static void byte2hex(byte b, StringBuffer buf) {
        char[] hexChars = { '0', '1', '2', '3', '4', '5', '6', '7', '8',
			'9', 'A', 'B', 'C', 'D', 'E', 'F' };
        int high = ((b & 0xf0) >> 4);
        int low = (b & 0x0f);
        buf.append(hexChars[high]);
        buf.append(hexChars[low]);
    }
	
    /*
     * Converts a byte array to hex string
     */
    private static String toHexString(byte[] block) {
        StringBuffer buf = new StringBuffer();
		
        int len = block.length;
		
        for (int i = 0; i < len; i++) {
			byte2hex(block[i], buf);
			if (i < len-1) {
				buf.append(":");
			}
        }
        return buf.toString();
    }
}