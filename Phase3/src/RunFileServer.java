/* Driver program for FileSharing File Server */

public class RunFileServer {
	
	public static void main(String[] args) {
		if (args.length == 3) {
			try {
				FileServer server = new FileServer(Integer.parseInt(args[0]),
												   args[1],
												   Integer.parseInt(args[2]));
				server.start();
			}
			catch (NumberFormatException e) {
				System.out.println("Enter valid integer port numbers.");
				System.out.println("Usage: java RunFileServer <port> <Group Server address> <Groups Server port>");
			}
		}
		else {
			System.out.println("Enter correct number of arguments.");
			System.out.println("Usage: java RunFileServer <port> <Group Server address> <Group Server port>");
		}
	}
}
