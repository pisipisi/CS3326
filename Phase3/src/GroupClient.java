/* Implements the GroupClient Interface */

import java.util.ArrayList;
import java.util.List;
import java.io.ObjectInputStream;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.math.BigInteger;

public class GroupClient extends Client implements GroupClientInterface {
	private Key sessionKey;
	
	public boolean getSessionKey() {
		Security.addProvider(new BouncyCastleProvider());
		try {
			// create symmetric shared key for this session
			Cipher sharedCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
			KeyGenerator keyGenAES = KeyGenerator.getInstance("AES", "BC");
			SecureRandom rand = new SecureRandom();
			byte b[] = new byte[20];
			rand.nextBytes(b);
			keyGenAES.init(128, rand);
			sessionKey = keyGenAES.generateKey();
			// get challenge from same generator as key
			int challenge = (Integer)rand.nextInt();
			
			KeyPack keyPack = new KeyPack(challenge, sessionKey);
			
			// create an object for use as IV
			byte IVarray[] = new byte[16];
			SecureRandom IV = new SecureRandom();
			IV.nextBytes(IVarray);
			
			// encrypt key and challenge with Group Client's public key
			Envelope message = null, ciphertext = null, response = null;
			Cipher msgCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
			msgCipher.init(Cipher.ENCRYPT_MODE, getPubKey());
			SealedObject outCipher = new SealedObject(keyPack, msgCipher);
			
			// send it to the server with IV array
			message = new Envelope("KCG");
			message.addObject(outCipher);
			message.addObject(IVarray);
			output.writeObject(message);
			// get the response from the server
			response = (Envelope)input.readObject();

			// decrypt and verify challenge value + 1 was returned
			if (response.getMessage().equals("OK")) {
				byte challResp[] = (byte[])response.getObjContents().get(0);
				// decrypt challenge
				Cipher sc = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
				sc.init(Cipher.DECRYPT_MODE, sessionKey, new IvParameterSpec(IVarray));
				byte[] plainText = sc.doFinal(challResp);
				if (new BigInteger(plainText).intValue() == challenge + 1) {
					return true;
				}
				else {
					System.out.println("Session Key challenge response failed.");
				}
			}
		}
		catch(Exception e) {
			System.out.println("Error: " + e);
			e.printStackTrace();
		}
		return false;
	}
	
	public PublicKey getPubKey() {
		try {
			Envelope message = null, response = null;			
			// Tell the server to return its public key.
			message = new Envelope("GETPUBKEY");
			output.writeObject(message);
			// Get the response from the server
			response = (Envelope)input.readObject();
			// Successful response
			if(response.getMessage().equals("OK"))
			{
				//If there is a public key in the Envelope, return it 
				ArrayList<Object> temp = null;
				temp = response.getObjContents();
				
				if(temp.size() == 1) {
					return (PublicKey)temp.get(0);
				}
			}
			return null;
		}
		catch(Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return null;
		}
	}

	public UserToken getToken(String username, char[] password) {
		try {
			UserToken token = null;
			Envelope message = null, response = null;
		 		 	
			// Tell the server to return a token.
			message = new Envelope("GET");
			message.addObject(username); // Add username string
			message.addObject(password); // Add user's password
		
			// Get the response from the server
			response = secureMsg(message);
			
			System.out.println(response.getMessage());
			// Successful response
			if (response.getMessage().equals("OK")) {
				// If there is a token in the Envelope, return it 
				ArrayList<Object> temp = null;
				temp = response.getObjContents();
				
				if(temp.size() == 1) {
					token = (UserToken)temp.get(0);
					return token;
				}
			}
			
			return null;
		}
		catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return null;
		}
	}
	 
	 public boolean createUser(String username, char[] password, UserToken token) {
		 try {
			Envelope message = null, response = null;
			//Tell the server to create a user
			message = new Envelope("CUSER");
			message.addObject(username); //Add user name string
			message.addObject(password); //Add user password
			message.addObject(token); //Add the requester's token
			 
			 response = secureMsg(message);
			
			//If server indicates success, return true
			if(response.getMessage().equals("OK")) {
				return true;
			}
			
			return false;
		}
		catch(Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	}
	 
	 public boolean deleteUser(String username, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
			 
				//Tell the server to delete a user
				message = new Envelope("DUSER");
				message.addObject(username); //Add user name
				message.addObject(token);  //Add requester's token
				
				response = secureMsg(message);
				
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				}
				
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }
	 
	 public boolean createGroup(String groupname, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to create a group
				message = new Envelope("CGROUP");
				message.addObject(groupname); //Add the group name string
				message.addObject(token); //Add the requester's token
				
				response = secureMsg(message);
				
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				}
				
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }
	 
	 public boolean deleteGroup(String groupname, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to delete a group
				message = new Envelope("DGROUP");
				message.addObject(groupname); //Add group name string
				message.addObject(token); //Add requester's token
				
				response = secureMsg(message);
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				}
				
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }
	 
	 @SuppressWarnings("unchecked")
	public List<String> listMembers(String group, UserToken token)
	 {
		 try
		 {
			 Envelope message = null, response = null;
			 //Tell the server to return the member list
			 message = new Envelope("LMEMBERS");
			 message.addObject(group); //Add group name string
			 message.addObject(token); //Add requester's token

			 response = secureMsg(message);
			 
			 //If server indicates success, return the member list
			 if(response.getMessage().equals("OK"))
			 { 
				return (List<String>)response.getObjContents().get(0); //This cast creates compiler warnings. Sorry.
			 }
				
			 return null;
			 
		 }
		 catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return null;
			}
	 }
	 
	 public boolean addUserToGroup(String username, String groupname, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to add a user to the group
				message = new Envelope("AUSERTOGROUP");
				message.addObject(username); //Add user name string
				message.addObject(groupname); //Add group name string
				message.addObject(token); //Add requester's token
				
				response = secureMsg(message);
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				}
				
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }
	 
	 public boolean deleteUserFromGroup(String username, String groupname, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to remove a user from the group
				message = new Envelope("RUSERFROMGROUP");
				message.addObject(username); //Add user name string
				message.addObject(groupname); //Add group name string
				message.addObject(token); //Add requester's token
				
				response = secureMsg(message);
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				}
				
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }

	public Envelope secureMsg (Envelope message) {
		try {
			// Encrypt original Envelope
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
			SecureRandom IV = new SecureRandom();
			byte IVarray[] = new byte[16];
			IV.nextBytes(IVarray);
			cipher.init(Cipher.ENCRYPT_MODE, sessionKey, new IvParameterSpec(IVarray));
			SealedObject outCipher = new SealedObject(message, cipher);
			// Create new Envelope with encrypted data and IV
			Envelope cipherMsg = new Envelope("ENV");
			Envelope encResponse = null;
			cipherMsg.addObject(outCipher);
			cipherMsg.addObject(IVarray);
			output.writeObject(cipherMsg);
			// Get and decrypt response
			encResponse = (Envelope)input.readObject();
			if (encResponse.getMessage().equals("ENV")) {
				// Decrypt Envelope contents
				SealedObject inCipher = (SealedObject)encResponse.getObjContents().get(0);
				IVarray = (byte[])encResponse.getObjContents().get(1);
				String algo = inCipher.getAlgorithm();
				Cipher envCipher = Cipher.getInstance(algo);
				envCipher.init(Cipher.DECRYPT_MODE, sessionKey, new IvParameterSpec(IVarray));
				return (Envelope)inCipher.getObject(envCipher);
			}
		}
		catch(Exception e) {
			System.out.println("Error: " + e);
			e.printStackTrace();
		}
		return null;
	}
}
