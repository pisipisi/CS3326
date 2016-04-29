import java.util.Scanner; // Scanner class required for user input
import java.io.Console;
import java.util.List;
import java.util.Arrays;
import java.security.*;
import javax.crypto.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class GroupClientUI {
	GroupClient gc = new GroupClient();
	
	public boolean launchUI(UserToken token, String serverName, int portNumber) {
		if (gc.connect(serverName, portNumber)) {
			Scanner console = new Scanner(System.in); // Scanner object for input
			String userName = token.getSubject();
			String aUserName, aGroupName;
			String inputString;
			int menuChoice;
			boolean exitKey = false;
			List<String> aList;
			final int MAXUSERLENGTH = 32;
			final int MAXGROUPLENGTH = 32;
			
			// get session key
			if (gc.getSessionKey()) {
				System.out.println("Session key obtained. Connection to server encrypted.");
			}
			else {
				System.out.println("Error while obtaining session key. Exiting.");
				exitKey = true;
			}
			
			while (!exitKey) {
				System.out.print("Enter 1 to create a user,\n" +
								 "enter 2 to delete a user,\n" +
								 "enter 3 to create a group,\n" +
								 "enter 4 to delete a group,\n" +
								 "enter 5 to list the members of a group,\n" +
								 "enter 6 to add a user to a group,\n" +
								 "enter 7 to delete a user from a group,\n" +
								 "enter 0 to disconnect from Group Server:\n" +
								 userName + "> ");
				inputString = console.nextLine();
				
				try {
					menuChoice = Integer.parseInt(inputString);
				}
				catch(Exception e) {
					menuChoice = -1;
				}
				
				switch (menuChoice) {
					case 1:
						if (token.getGroups().contains("ADMIN")) {
							aUserName = getNonEmptyString("Enter the username to be added: ", MAXUSERLENGTH);
							char newPW[] = getPasswordPair();
							
							if (gc.createUser(aUserName, newPW, token)) {
								System.out.println("Added " + aUserName + " to the User List.");
							}
							else {
								System.out.println("Error adding user - name already exists.");
							}
						}
						else {
							System.out.println("Forbidden operation. You must be an ADMIN to create a user.");
						}
						break;
					case 2:
						if (token.getGroups().contains("ADMIN")) {
							aUserName = getNonEmptyString("Enter the username to be deleted: ", MAXUSERLENGTH);
							if (gc.deleteUser(aUserName, token)) {
								System.out.println("Deleted " + aUserName + " from the User List.");
							}
							else {
								System.out.println("Error deleting user - unknown username.");
							}
						}
						else {
							System.out.println("Forbidden operation. You must be an ADMIN to delete a user.");
						}
						break;
					case 3:
						aGroupName = getNonEmptyString("Enter the group name to be created: ", MAXGROUPLENGTH);
						if (gc.createGroup(aGroupName, token)) {
							System.out.println("Added the group " + aGroupName + " to your Group List.");
						}
						else {
							System.out.println("Error creating group - group name already exists.");
						}
						break;
					case 4:
						aGroupName = getNonEmptyString("Enter the group name to be deleted: ", MAXGROUPLENGTH);
						if (gc.deleteGroup(aGroupName, token)) {
							System.out.println("Deleted the group " + aGroupName + " from your Group List.");
						}
						else {
							System.out.println("Forbidden operation. You must be the owner of a group to delete it.");
						}
						break;
					case 5:
						aGroupName = getNonEmptyString("Enter the group name: ", MAXGROUPLENGTH);
						aList = gc.listMembers(aGroupName, token);
						if (aList != null) {
							for (String s: aList) {
								System.out.println(s);
							}
						}
						else {
							System.out.println("Error. You are not the owner of group " +
											   aGroupName + ".");
						}
						break;
					case 6:
						aUserName = getNonEmptyString("Enter the username: ", MAXUSERLENGTH);
						aGroupName = getNonEmptyString("Enter the group name: ", MAXGROUPLENGTH);
						if (gc.addUserToGroup(aUserName, aGroupName, token)) {
							System.out.println("Added " + aUserName + " to group " + aGroupName + ".");
						}
						else {
							System.out.println("Error adding user to group - check username and group name.");
						}
						break;
					case 7:
						aUserName = getNonEmptyString("Enter the username: ", MAXUSERLENGTH);
						aGroupName = getNonEmptyString("Enter the group name: ", MAXGROUPLENGTH);
						if (gc.deleteUserFromGroup(aUserName, aGroupName, token)) {
							System.out.println("Removed " + aUserName + " from group " + aGroupName + ".");
						}
						else {
							System.out.println("Error deleting user from group - check that the user is member of that group.");
						}
						break;
					case 0:
						System.out.println("Disconnecting from Group Server...");
						gc.disconnect();
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
			System.out.println("Error connecting to Group Server");
			return false;
		}
	}
	
	public char[] getPasswordPair() {
		// Get password
		Console console = System.console();
		char pwArray1[];
		do {
			pwArray1 = console.readPassword("Enter a new password: ");
			char pwArray2[] = console.readPassword("Re-enter the password: ");
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
		// Return password
		return pwArray1;
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
}