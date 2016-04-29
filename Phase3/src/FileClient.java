/* FileClient provides all the client functionality regarding the file server */

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.List;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.math.BigInteger;

public class FileClient extends Client implements FileClientInterface {
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
			message = new Envelope("KCF");
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
			// If successful response, return public key
			if(response.getMessage().equals("OK")) {
				return (PublicKey)response.getObjContents().get(0);
			}
			return null;
		}
		catch(Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return null;
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
	
	public boolean delete(String filename, String group, UserToken token) {
		String remotePath;
		if (filename.charAt(0)=='/') {
			remotePath = filename.substring(1);
		}
		else {
			remotePath = filename;
		}
		Envelope env = new Envelope("DELETEF"); // Success
	    env.addObject(remotePath);
	    env.addObject(group);
	    env.addObject(token);
	    try {
			env = secureMsg(env);

			if (env.getMessage().compareTo("OK")==0) {
				System.out.printf("File %s deleted successfully\n", filename);				
			}
			else {
				System.out.printf("Error deleting file %s (%s)\n", filename, env.getMessage());
				return false;
			}			
		}
		catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}	    	
		return true;
	}

	public boolean download(String sourceFile, String destFile, String group, UserToken token) {
		if (sourceFile.charAt(0) == '/') {
			sourceFile = sourceFile.substring(1);
		}

		File file = new File(destFile);
		try {
			if (!file.exists()) {
				file.createNewFile();
				FileOutputStream fos = new FileOutputStream(file);
				
				Envelope env = new Envelope("DOWNLOADF"); // Success
				env.addObject(sourceFile);
				env.addObject(group);
				env.addObject(token);

				env = secureMsg(env);
								
				while (env.getMessage().compareTo("CHUNK")==0) { 
					fos.write((byte[])env.getObjContents().get(0), 0, (Integer)env.getObjContents().get(1));
					System.out.printf(".");
					env = new Envelope("DOWNLOADF"); // Success
					
					env = secureMsg(env);
				}										
				fos.close();
				
				if (env.getMessage().compareTo("EOF")==0) {
					fos.close();
					System.out.printf("\nTransfer successful file %s\n", sourceFile);
					env = new Envelope("OK"); //Success

					// send envelope, don't need response so don't use secureMsg
					try {
						// Encrypt original Envelope
						Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
						SecureRandom IV = new SecureRandom();
						byte IVarray[] = new byte[16];
						IV.nextBytes(IVarray);
						cipher.init(Cipher.ENCRYPT_MODE, sessionKey, new IvParameterSpec(IVarray));
						SealedObject outCipher = new SealedObject(env, cipher);
						// Create new Envelope with encrypted data and IV
						Envelope cipherMsg = new Envelope("ENV");
						Envelope encResponse = null;
						cipherMsg.addObject(outCipher);
						cipherMsg.addObject(IVarray);
						output.writeObject(cipherMsg);
					}
					catch(Exception e) {
						System.out.println("Error: " + e);
						e.printStackTrace();
					}

				}
				else {
						System.out.printf("Error reading file %s (%s)\n", sourceFile, env.getMessage());
						file.delete();
						return false;								
				}
			}    
			 
			else {
				System.out.printf("Error couldn't create file %s\n", destFile);
				return false;
			}
		}
		catch (IOException e1) {
			
			System.out.printf("Error couldn't create file %s\n", destFile);
			return false;
		}
		catch (Exception e1) {
			e1.printStackTrace();
		}
		return true;
	}

	@SuppressWarnings("unchecked")
	public List<String> listFiles(UserToken token) {
		try {
			Envelope message = null, env = null;
			message = new Envelope("LFILES");
			message.addObject(token); // Add requester's token

			env = secureMsg(message);
			
			if (env.getMessage().equals("OK")) { 
				return (List<String>)env.getObjContents().get(0); // This cast creates compiler warnings. Sorry.
			}
			
			return null;
		}
		catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return null;
		}
	}

	@SuppressWarnings("unchecked")
	public List<String> listGroups(UserToken token) {
		try {
			Envelope message = null, env = null;
			// Tell the server to return the group list
			message = new Envelope("LGROUPS");
			message.addObject(token); // Add requester's token
			
			env = secureMsg(message);
			
			// If server indicates success, return the member list
			if (env.getMessage().equals("OK")) { 
				return (List<String>)env.getObjContents().get(0); // This cast creates compiler warnings. Sorry.
			}
			
			return null;
		}
		catch(Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return null;
		}
	}

	@SuppressWarnings("unchecked")
	public List<String> changeGroup(String group, UserToken token) {
		try {
			Envelope message = null, env = null;
			message = new Envelope("CGROUP");
			message.addObject(group); // Add requester's group
			message.addObject(token); // Add requester's token
			
			env = secureMsg(message);

			// If server indicates success, return the group that it was changed to
			if (env.getMessage().equals("OK")) { 
				return (List<String>)env.getObjContents().get(0); //This cast creates compiler warnings. Sorry.
			}
			return null;			 
		}
		catch(Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return null;
		}
	}

	public boolean upload(String sourceFile, String destFile, String group, UserToken token) {
		if (destFile.charAt(0) != '/') {
			 destFile = "/" + destFile;
		}
		
		try {
			Envelope message = null, env = null;
			message = new Envelope("UPLOADF");
			message.addObject(destFile);
			message.addObject(group);
			message.addObject(token); // Add requester's token

			FileInputStream fis = new FileInputStream(sourceFile);

			env = secureMsg(message);

			// If server indicates success, return the member list
			if (env.getMessage().equals("READY")) { 
				System.out.printf("Meta data upload successful\n");
			}
			else {				
				System.out.printf("Upload failed: %s\n", env.getMessage());
				return false;
			}
			 
			do {
				byte[] buf = new byte[4096];
				if (env.getMessage().compareTo("READY") != 0) {
					System.out.printf("Server error: %s\n", env.getMessage());
					return false;
				}
				message = new Envelope("CHUNK");
				int n = fis.read(buf); // can throw an IOException
				if (n > 0) {
					System.out.printf(".");
				}
				else if (n < 0) {
					System.out.println("Read error");
					return false;
				}

				message.addObject(buf);
				message.addObject(new Integer(n));

				env = secureMsg(message);
			}
			while (fis.available() > 0);		 
					 
			if (env.getMessage().compareTo("READY") == 0) { 
				message = new Envelope("EOF");
				
				env = secureMsg(message);
				
				if (env.getMessage().compareTo("OK") == 0) {
					System.out.printf("\nFile data upload successful\n");
				}
				else {
					 System.out.printf("\nUpload failed: %s\n", env.getMessage());
					 return false;
				}
			}
			else {
				 System.out.printf("Upload failed: %s\n", env.getMessage());
				 return false;
			}
		}
		catch(Exception e1) {
			System.err.println("Error: " + e1.getMessage());
			e1.printStackTrace(System.err);
			return false;
		}
		return true;
	}
}
