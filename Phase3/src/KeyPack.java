import java.security.*;
import javax.crypto.*;

public class KeyPack implements java.io.Serializable {
	private static final long serialVersionUID = -1931037726335089122L;
	private int challenge;
	private Key secretKey;	
	
	public KeyPack(int _challenge, Key _secretKey) {
		challenge = _challenge;
		secretKey = _secretKey;
	}
	
	public int getChallenge()
	{
		return challenge;
	}
	
	public Key getSecretKey()
	{
		return secretKey;
	}
}
