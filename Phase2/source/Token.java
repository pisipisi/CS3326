import java.util.List;

public class Token implements UserToken, java.io.Serializable
{
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private String issuer;
	private String subject;
	private List<String> groups;

	public Token(String anIssuer, String aSubject, List<String> theGroups)
	{
		issuer = new String(anIssuer);
		subject = new String(aSubject);
		groups = theGroups; // better way to instantiate?
	}

	/**
     * This method should return a string describing the issuer of
     * this token.  This string identifies the group server that
     * created this token.  For instance, if "Thanh" requests a token
     * from the group server "Server1", this method will return the
     * string "Server1".
     *
     * @return The issuer of this token
     *
     */
    public String getIssuer()
    {
		//return "getIssuer stub";
    	return issuer;
    }


    /**
     * This method should return a string indicating the name of the
     * subject of the token.  For instance, if "Thanh" requests a
     * token from the group server "Server1", this method will return
     * the string "Thanh".
     *
     * @return The subject of this token
     *
     */
    public String getSubject()
    {
    	//return "getSubject stub";
    	return subject;
    }


    /**
     * This method extracts the list of groups that the owner of this
     * token has access to.  If "Thanh" is a member of the groups "G1"
     * and "G2" defined at the group server "Server1", this method
     * will return ["G1", "G2"].
     *
     * @return The list of group memberships encoded in this token
     *
     */
    public List<String> getGroups()
    {
    	//String[] words = {"this", "is", "the", "getGroups", "stub"};
		//List<String> wordList = Arrays.asList(words);
		//return wordList;
		return groups;
    }

}