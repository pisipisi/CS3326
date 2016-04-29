import java.util.List;
import java.util.Arrays;
import java.lang.StringBuilder;

public class Token implements UserToken, java.io.Serializable
{
	private String issuer;
	private String subject;
	private List<String> groups;
	private byte[] signature;

	public Token(String anIssuer, String aSubject, List<String> theGroups) {
		issuer = new String(anIssuer);
		subject = new String(aSubject);
		groups = theGroups;
	}

	public Token(String anIssuer, String aSubject, List<String> theGroups, byte[] theSignature) {
		issuer = new String(anIssuer);
		subject = new String(aSubject);
		groups = theGroups;
		signature = theSignature;
	}

	/**
     * This method should return a string describing the issuer of
     * this token.  This string identifies the group server that
     * created this token.  For instance, if "Alice" requests a token
     * from the group server "Server1", this method will return the
     * string "Server1".
     *
     * @return The issuer of this token
     *
     */
    public String getIssuer() {
    	return issuer;
    }

    /**
     * This method should return a string indicating the name of the
     * subject of the token.  For instance, if "Alice" requests a
     * token from the group server "Server1", this method will return
     * the string "Alice".
     *
     * @return The subject of this token
     *
     */
    public String getSubject() {
    	return subject;
    }

    /**
     * This method extracts the list of groups that the owner of this
     * token has access to.  If "Alice" is a member of the groups "G1"
     * and "G2" defined at the group server "Server1", this method
     * will return ["G1", "G2"].
     *
     * @return The list of group memberships encoded in this token
     *
     */
    public List<String> getGroups() {
		return groups;
    }
	
	public byte[] getSignature() {
		return signature;
	}
	
	public void setSignature(byte[] sig) {
		signature = sig;
	}
	
	public String getContents() {
		StringBuilder contents = new StringBuilder(issuer);
		contents.append(subject);
		for (int i = 0; i < groups.size(); i++) {
			contents.append(groups.get(i));
		}
		return contents.toString();
	}
}