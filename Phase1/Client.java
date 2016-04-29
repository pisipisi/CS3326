import javax.crypto.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.*;
import java.util.Random;
import java.util.Scanner;
public class Client {
    private static Scanner in;
    private static Key AESKey;
    private static Key DESKey;
    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        in = new Scanner(System.in);
        System.out.print("Please enter text: ");
        String s = in.nextLine();
      
        //call the static factory method to create a DES instance
        try {
        	// Generate DES key
            KeyGenerator keyGenDES = KeyGenerator.getInstance("DES", "BC");
            SecureRandom rand = new SecureRandom();
            byte b[] = new byte[20];
            rand.nextBytes(b);
            keyGenDES.init(64,rand);
            DESKey = keyGenDES.generateKey();
            // Encrypt the text 
            Cipher desCipher = Cipher.getInstance("DES");
            desCipher.init(Cipher.ENCRYPT_MODE, DESKey);
            byte[] encrypted = desCipher.doFinal(s.getBytes());
            System.err.println("DES Encrypted: " + new String(encrypted));
            
         // Decrypt the text
            desCipher.init(Cipher.DECRYPT_MODE, DESKey);
            String decrypted = new String(desCipher.doFinal(encrypted));
            System.err.println("DES Decrypted: " + new String(decrypted));
        } catch(Exception e) {
            System.out.println("Error: " + e);
            e.printStackTrace();
        }
          
        //call the static factory method to create a AES instance
        try {
            
            // Generate 128-bit AES key
            KeyGenerator keyGenAES = KeyGenerator.getInstance("AES", "BC");
            SecureRandom rand = new SecureRandom();
            byte b[] = new byte[20];
            rand.nextBytes(b);
            keyGenAES.init(128,rand);
            AESKey = keyGenAES.generateKey();
            // Encrypt the text 
            Cipher aesCipher = Cipher.getInstance("AES");
            aesCipher.init(Cipher.ENCRYPT_MODE, AESKey);
            byte[] encrypted = aesCipher.doFinal(s.getBytes());
            System.err.println("AES Encrypted: " + new String(encrypted));
            
            // Decrypt the text
            aesCipher.init(Cipher.DECRYPT_MODE, AESKey);
            String decrypted = new String(aesCipher.doFinal(encrypted));
            System.err.println("AES Decrypted: " + new String(decrypted));
        } catch(Exception e) {
            System.out.println("Error: " + e);
            e.printStackTrace();
        }   
        String[] arrayString = new String[100];
        for (int i = 0; i < 100; i++) {
        	arrayString[i] = stringGen();
        }
        System.out.println("-----------------------------------");
        System.out.println("Extra Credit");
        System.out.println("-----------------------------------");
        System.out.println("Generated 100 array String");
        System.out.println("-----------------------------------");
        System.out.println("Encrypting all 100 strings using DES");
        long desStartTime = System.currentTimeMillis();
        for (int i = 0; i < 100; i++) {
        	try {
        		// Generate DES key
        		KeyGenerator keyGenDES = KeyGenerator.getInstance("DES", "BC");
        		SecureRandom rand = new SecureRandom();
        		byte b[] = new byte[20];
        		rand.nextBytes(b);
        		keyGenDES.init(64,rand);
        		DESKey = keyGenDES.generateKey();
        		// Encrypt the text 
        		Cipher desCipher = Cipher.getInstance("DES");
        		desCipher.init(Cipher.ENCRYPT_MODE, DESKey);
        		byte[] encrypted = desCipher.doFinal(arrayString[i].getBytes());
        		//arrayString[i] = new String(encrypted);
        	} catch(Exception e) {
        		System.out.println("Error: " + e);
	            e.printStackTrace();
        	}
        }
        long desEndTime   = System.currentTimeMillis();
        long desTotalTime = desEndTime - desStartTime;
        System.out.println("Encrypt time: " + desTotalTime);
        System.out.println("-----------------------------------");
        System.out.println("Encrypting all 100 strings using AES");
        long aesStartTime = System.currentTimeMillis();
        for (int i = 0; i < 100; i++) {
        	try {
                
                // Generate 128-bit AES key
                KeyGenerator keyGenAES = KeyGenerator.getInstance("AES", "BC");
                SecureRandom rand = new SecureRandom();
                byte b[] = new byte[20];
                rand.nextBytes(b);
                keyGenAES.init(128,rand);
                AESKey = keyGenAES.generateKey();
                // Encrypt the text 
                Cipher aesCipher = Cipher.getInstance("AES");
                aesCipher.init(Cipher.ENCRYPT_MODE, AESKey);
                byte[] encrypted = aesCipher.doFinal(arrayString[i].getBytes());
            } catch(Exception e) {
                System.out.println("Error: " + e);
                e.printStackTrace();
            }  
        }
        long aesEndTime   = System.currentTimeMillis();
        long aesTotalTime = aesEndTime - aesStartTime;
        System.out.println("Encrypt time: " + aesTotalTime);
    }
    
    public static String stringGen() {
    	char[] chars = "abcdefghijklmnopqrstuvwxyz".toCharArray();
    	StringBuilder sb = new StringBuilder();
    	Random random = new Random();
    		
    	for (int i = 0; i < 50; i++) {
    		char c = chars[random.nextInt(chars.length)];
    		sb.append(c);
    	}
    	return sb.toString();
    }
}