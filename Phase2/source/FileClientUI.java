import java.util.Scanner; // Scanner class required for user input
import java.util.List;

public class FileClientUI
{
	FileClient fc = new FileClient();
	private Scanner console;
	private static Scanner scan;
	
	public boolean launchUI(UserToken token, String serverAddress, int portNumber)
	{
		if (fc.connect(serverAddress, portNumber))
		{
			console = new Scanner(System.in);
			String userName = token.getSubject();
			int menuChoice = 0;
			boolean exitKey = false;
			final int MAXGROUPLENGTH = 32;
			final int MAXPATHLENGTH = 256;
			List<String> aList;
			String groupName;
			String currentGroup = new String();
			String userPrompt;
			String sourceFileName;
			String destFileName;

			
			while (!exitKey)
			{
				/* FileClient methods:
				 * public boolean delete(String filename, UserToken token)
				 * public boolean download(String sourceFile, String destFile, UserToken token)
				 * public List<String> listFiles(UserToken token)
				 * public boolean upload(String sourceFile, String destFile, String group, UserToken token)
				 */
				if (currentGroup.length() > 0)
				{
					userPrompt = userName + "/" + currentGroup;
				}
				else
				{
					userPrompt = userName;
				}
				System.out.print("Enter 1 to list the groups you belong to,\n" +
								 "enter 2 to change the current group to traverse,\n" +
								 "enter 3 to list files,\n" +
								 "enter 4 to upload a file to the File Server,\n" +
								 "enter 5 to download a file from the File Server,\n" +
								 "enter 6 to delete a file from the File Server,\n" +
								 "enter 7 to listen to a file from the File Server,\n" +
								 "enter 0 to disconnect from File Server...\n" +
								 userPrompt + "> ");
				String inputString = console.nextLine();
				
				try
				{
					menuChoice = Integer.parseInt(inputString);
				}
				catch(Exception e)
				{
					menuChoice = -1;
				}
				
				switch (menuChoice)
				{
					case 1:
						aList = fc.listGroups(token);
						if (aList != null)
						{
							for (String s: aList)
							{
								System.out.println(s);
							}
						}
						else
						{
							System.out.println("Error - user has no groups. Please add groups in Group Server.");
						}
						break;
					case 2:
						groupName = getNonEmptyString("Enter the group name to change to...\n> ", MAXGROUPLENGTH);
						aList = fc.changeGroup(groupName, token);
						if (aList != null)
						{
							for (String s: aList)
							{
								System.out.println("Changed to group " + s + ".");
								currentGroup = s;
							}
						}
						else
						{
							System.out.println("Error - please add groups to Group Server.");
						}
						break;
					case 3:
						aList = fc.listFiles(token);
						if (aList != null && aList.size() != 0)
						{
							for (String s: aList)
							{
								System.out.println(s);
							}
						}
						else
						{
							System.out.println("No files present.");
						}
						break;
					case 4:
						if (currentGroup.length() > 0)
						{
							sourceFileName = getNonEmptyString("Enter source file path...\n> ", MAXPATHLENGTH);
							destFileName = getNonEmptyString("Enter destination file path...\n> ", MAXPATHLENGTH);
							if (fc.upload(sourceFileName, destFileName, currentGroup, token))
							{
								System.out.println(destFileName + " successfully uploaded to group " + currentGroup + ".");
							}
							else
							{
								System.out.println("Error uploading " + destFileName + " to File Server.");
							}
						}
						else
						{
							System.out.println("You must pick a group for your workspace (option 2).");
						}
						break;
					case 5:
						if (currentGroup.length() > 0)
						{
							sourceFileName = getNonEmptyString("Enter source file path...\n> ", MAXPATHLENGTH);
							destFileName = getNonEmptyString("Enter destination file path...\n> ", MAXPATHLENGTH);
							if (fc.download(sourceFileName, destFileName, currentGroup, token))
							{
								System.out.println(destFileName + " successfully downloaded.");
							}
						}
						else
						{
							System.out.println("You must pick a group for your workspace (option 2).");
						}
						break;
					case 6:
						if (currentGroup.length() > 0)
						{
							sourceFileName = getNonEmptyString("Enter filename to delete...\n> ", MAXPATHLENGTH);
							if (fc.delete(sourceFileName, currentGroup, token))
							{
								System.out.println(sourceFileName + " successfully deleted.");
							}
						}
						else
						{
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
		else // error connecting
		{
			System.out.println("Error connecting to File Server at " +
							   serverAddress + " port " + portNumber + ".");
			return false;
		}
	}
	
	public static String getNonEmptyString(String prompt, int maxLength)
	{
		String str = "";
		scan = new Scanner(System.in);
		
		System.out.print(prompt);        
		
		while (str.length() == 0)
		{
			str = scan.nextLine();
			
			if (str.length() == 0)
			{
				System.out.print(prompt);
			}
			else if (str.length() > maxLength)
			{
				System.out.println("Maximum length allowed is " + maxLength + " characters. Please re-enter.");
				System.out.print(prompt);
				str = "";
			}
		}
		
		return str;
	}
}