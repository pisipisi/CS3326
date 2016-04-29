import java.io.Console;
import java.util.Scanner; // Scanner class required for user input

public class SimpleUI
{
	//   private static Scanner console;
	private static Scanner scan;

	public static void main(String[] args)
    {
		loginMenu();
	}
	
	public static void loginMenu()
	{
		GroupClient gc = new GroupClient();
		scan = new Scanner(System.in);
		Console console = System.console(); // for password input

		String inputString;
		int menuChoice;
		boolean exitKey = false;
		boolean hasToken = false;
		String userName = new String();
		UserToken userToken = null;
		
		while (!exitKey)
		{
			System.out.print("Enter 1 to login,\nenter 2 to exit...\n> ");
			inputString = scan.nextLine();
			
			try
			{
				menuChoice = Integer.parseInt(inputString);
			}
			catch(Exception e)
			{
				menuChoice = -1;
			}
			
			if (menuChoice == 1)
			{
				System.out.print("Enter your username to login...\n> ");
				userName = scan.nextLine();
				char pwArray[] = console.readPassword("Enter your password...\n> ");
				// connect to group server and get token
				// may want to prompt user here for server name, port?
				gc.connect("localhost", 2222);
				if (gc.isConnected()) // check that server is running
				{
					userToken = gc.getToken(userName, pwArray);
					if (userToken == null) // no login for that name
					{
						System.out.println("Username not recognized. Contact Admin.");
						gc.disconnect();
					}
					else // has a valid token, can disconnect from gc
					{
						hasToken = true;
						gc.disconnect();
					}
				}
				else
				{
					System.out.println("Error - Group Server not running. Contact Admin.");
				}
			}
			else if (menuChoice == 2)
			{
				System.out.println("Exiting...");
				exitKey = true;
			}
			else
			{
				System.out.println("Unknown command. Please try again.");
			}
			
			while (hasToken)
			{
				System.out.print("Main menu:\n" +
								 "Enter 1 to connect to the File Server,\n" +
								 "enter 2 to connect to the Group Server,\n" +
								 "enter 3 to logout...\n" +
								 userName + "> ");
				inputString = scan.nextLine();
				
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
						FileClientUI fcu = new FileClientUI();
						fcu.launchUI(userToken, "localhost", 1111);
						break;
					case 2:
						GroupClientUI gcu = new GroupClientUI();
						// may want to prompt user here for server name, port
						gcu.launchUI(userToken, "localhost", 2222);
						hasToken = false;
						break;
					case 3:
						System.out.println("Logging out...");
						hasToken = false;
						userToken = null;
						break;
					default:
						System.out.println("Unknown command. Please try again.");
						break;
				}
			}  
		}
	}
}