package ntin.auth;


import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.security.Principal;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

import net.jradius.client.RadiusClient;
import net.jradius.client.auth.PAPAuthenticator;
import net.jradius.dictionary.Attr_NASPort;
import net.jradius.dictionary.Attr_NASPortType;
import net.jradius.dictionary.Attr_ReplyMessage;
import net.jradius.dictionary.Attr_UserName;
import net.jradius.dictionary.Attr_UserPassword;
import net.jradius.exception.RadiusException;
import net.jradius.exception.UnknownAttributeException;
import net.jradius.packet.AccessAccept;
import net.jradius.packet.AccessRequest;
import net.jradius.packet.RadiusPacket;
import net.jradius.packet.attribute.AttributeFactory;
import net.jradius.packet.attribute.AttributeList;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class RadiusLoginModule implements LoginModule {

	static {
		AttributeFactory
		.loadAttributeDictionary("net.jradius.dictionary.AttributeDictionaryImpl");
	}
	
	static Logger logger = LoggerFactory.getLogger(RadiusLoginModule.class);
	
	// initial state
	private Subject subject;
	private CallbackHandler callbackHandler;
//	private Map sharedState;
//	private Map options;

	// configurable option
	private boolean debug = false;

	// the authentication status
	private boolean succeeded = false;
	private boolean commitSucceeded = false;

	private String username;
	private char[] password;

	private RadiusPrincipal userPrincipal;
	
	// fields holding module options
	private String host;
	private int port;
	private String secret;

	/**
	 * Initialize this <code>LoginModule</code>.
	 * 
	 * <p>
	 * 
	 * @param subject
	 *            the <code>Subject</code> to be authenticated.
	 *            <p>
	 * 
	 * @param callbackHandler
	 *            a <code>CallbackHandler</code> for communicating with the end
	 *            user (prompting for user names and passwords, for example).
	 *            <p>
	 * 
	 * @param sharedState
	 *            shared <code>LoginModule</code> state.
	 *            <p>
	 * 
	 * @param options
	 *            options specified in the login <code>Configuration</code> for
	 *            this particular <code>LoginModule</code>.
	 */
	public void initialize(Subject subject, CallbackHandler callbackHandler,
			Map<String,?>  sharedState, Map<String,?>  options) {

		this.subject = subject;
		this.callbackHandler = callbackHandler;
//		this.sharedState = sharedState;
//		this.options = options;

		// initialize any configured options
		debug = "true".equalsIgnoreCase((String) options.get("debug"));
		
		if(debug) {
			logger.debug("Authenticate with Radius-Jaas Module; current subject(s):");
			for(Principal p: subject.getPrincipals()) {
				logger.debug(p.getName());
			}
		}
		
		// get host
		host = (String) options.get("host");
		if(host == null) {
			host = "127.0.0.1";
		}

		// get port
		String portStr = (String) options.get("port");
		if(portStr == null) {
			port = 1812;
		}
		else {
			try {
				port = Integer.parseInt(portStr);
			}
			catch (NumberFormatException e) {
				port = 1812;
			}
		}
		
		// get secret
		secret = (String) options.get("secret");
		if(secret == null) {
			logger.warn("Warning: Radius secret not set");
			secret = "";
		}
	}

	/**
	 * Authenticate the user by prompting for a user name and password.
	 * 
	 * <p>
	 * 
	 * @return true in all cases since this <code>LoginModule</code> should not
	 *         be ignored.
	 * 
	 * @exception FailedLoginException
	 *                if the authentication fails.
	 *                <p>
	 * 
	 * @exception LoginException
	 *                if this <code>LoginModule</code> is unable to perform the
	 *                authentication.
	 */
	public boolean login() throws LoginException {

		// prompt for a user name and password
		if (callbackHandler == null) {
			logger.error("Radius-Jaas: no callback handler provided");
			throw new LoginException("Error: no CallbackHandler available "
					+ "to garner authentication information from the user");
		}

		Callback[] callbacks = new Callback[2];
		callbacks[0] = new NameCallback("user name: ");
		callbacks[1] = new PasswordCallback("password: ", false);

		try {
			callbackHandler.handle(callbacks);
			username = ((NameCallback) callbacks[0]).getName();
			char[] tmpPassword = ((PasswordCallback) callbacks[1])
					.getPassword();
			if (tmpPassword == null) {
				// treat a NULL password as an empty password
				tmpPassword = new char[0];
			}
			password = new char[tmpPassword.length];
			System.arraycopy(tmpPassword, 0, password, 0, tmpPassword.length);
			((PasswordCallback) callbacks[1]).clearPassword();

			succeeded = authWithRadius(host, port, secret, username, password);
			if(succeeded) {
				return true;
			}
			else {
				throw new FailedLoginException("Incorrect username/password");
			}
		} catch(UnknownHostException e) {
			logger.error("Unknown Radius host");
			throw new LoginException("Unknown radius host");
		} catch (java.io.IOException ioe) {
			logger.error("Unknown Radius IOException: "+ioe.getMessage());
			throw new LoginException(ioe.toString());
		} catch (UnsupportedCallbackException uce) {
			throw new LoginException("Error: " + uce.getCallback().toString()
					+ " not available to garner authentication information "
					+ "from the user");
		}

	}

	/**
	 * <p>
	 * This method is called if the LoginContext's overall authentication
	 * succeeded (the relevant REQUIRED, REQUISITE, SUFFICIENT and OPTIONAL
	 * LoginModules succeeded).
	 * 
	 * <p>
	 * If this LoginModule's own authentication attempt succeeded (checked by
	 * retrieving the private state saved by the <code>login</code> method),
	 * then this method associates a <code>SamplePrincipal</code> with the
	 * <code>Subject</code> located in the <code>LoginModule</code>. If this
	 * LoginModule's own authentication attempted failed, then this method
	 * removes any state that was originally saved.
	 * 
	 * <p>
	 * 
	 * @exception LoginException
	 *                if the commit fails.
	 * 
	 * @return true if this LoginModule's own login and commit attempts
	 *         succeeded, or false otherwise.
	 */
	public boolean commit() throws LoginException {
		if (succeeded == false) {
			return false;
		} else {
			// add a Principal (authenticated identity)
			// to the Subject

			// assume the user we authenticated is the SamplePrincipal
			userPrincipal = new RadiusPrincipal(username);
			if (!subject.getPrincipals().contains(userPrincipal))
				subject.getPrincipals().add(userPrincipal);

			if (debug) {
				logger.debug("[RadiusPrincipal] added RadiusPrincipal("+username+") to Subject");
				logger.debug("Current subject(s):");
				for(Principal p: subject.getPrincipals()) {
					logger.debug(p.getName());
				}
			}

			// in any case, clean out state
			username = null;
			for (int i = 0; i < password.length; i++)
				password[i] = ' ';
			password = null;

			commitSucceeded = true;
			return true;
		}
	}

	/**
	 * <p>
	 * This method is called if the LoginContext's overall authentication
	 * failed. (the relevant REQUIRED, REQUISITE, SUFFICIENT and OPTIONAL
	 * LoginModules did not succeed).
	 * 
	 * <p>
	 * If this LoginModule's own authentication attempt succeeded (checked by
	 * retrieving the private state saved by the <code>login</code> and
	 * <code>commit</code> methods), then this method cleans up any state that
	 * was originally saved.
	 * 
	 * <p>
	 * 
	 * @exception LoginException
	 *                if the abort fails.
	 * 
	 * @return false if this LoginModule's own login and/or commit attempts
	 *         failed, and true otherwise.
	 */
	public boolean abort() throws LoginException {
		if (succeeded == false) {
			return false;
		} else if (succeeded == true && commitSucceeded == false) {
			// login succeeded but overall authentication failed
			succeeded = false;
			username = null;
			if (password != null) {
				for (int i = 0; i < password.length; i++)
					password[i] = ' ';
				password = null;
			}
			userPrincipal = null;
		} else {
			// overall authentication succeeded and commit succeeded,
			// but someone else's commit failed
			logout();
		}
		return true;
	}

	/**
	 * Logout the user.
	 * 
	 * <p>
	 * This method removes the <code>SamplePrincipal</code> that was added by
	 * the <code>commit</code> method.
	 * 
	 * <p>
	 * 
	 * @exception LoginException
	 *                if the logout fails.
	 * 
	 * @return true in all cases since this <code>LoginModule</code> should not
	 *         be ignored.
	 */
	public boolean logout() throws LoginException {

		subject.getPrincipals().remove(userPrincipal);
		succeeded = false;
		succeeded = commitSucceeded;
		username = null;
		if (password != null) {
			for (int i = 0; i < password.length; i++)
				password[i] = ' ';
			password = null;
		}
		userPrincipal = null;
		return true;
	}

	public static class RadiusPrincipal implements Principal,
			java.io.Serializable {

		private static final long serialVersionUID = 4686039977609569934L;

		private String name;

		/**
		 * Create a SamplePrincipal with a Sample username.
		 * 
		 * <p>
		 * 
		 * @param name
		 *            the Sample username for this user.
		 * 
		 * @exception NullPointerException
		 *                if the <code>name</code> is <code>null</code>.
		 */
		public RadiusPrincipal(String name) {
			if (name == null)
				throw new NullPointerException("illegal null input");

			this.name = name;
		}

		/**
		 * Return the Sample username for this <code>SamplePrincipal</code>.
		 * 
		 * <p>
		 * 
		 * @return the Sample username for this <code>SamplePrincipal</code>
		 */
		public String getName() {
			return name;
		}

		/**
		 * Return a string representation of this <code>SamplePrincipal</code>.
		 * 
		 * <p>
		 * 
		 * @return a string representation of this <code>SamplePrincipal</code>.
		 */
		@Override
		public String toString() {
			return ("RadiusPrincipal:  " + name);
		}

		/**
		 * Compares the specified Object with this <code>SamplePrincipal</code>
		 * for equality. Returns true if the given object is also a
		 * <code>SamplePrincipal</code> and the two SamplePrincipals have the
		 * same username.
		 * 
		 * <p>
		 * 
		 * @param o
		 *            Object to be compared for equality with this
		 *            <code>SamplePrincipal</code>.
		 * 
		 * @return true if the specified Object is equal equal to this
		 *         <code>SamplePrincipal</code>.
		 */
		@Override
		public boolean equals(Object o) {
			if (o == null)
				return false;

			if (this == o)
				return true;

			if (!(o instanceof RadiusPrincipal))
				return false;
			RadiusPrincipal that = (RadiusPrincipal) o;

			if (this.getName().equals(that.getName()))
				return true;
			return false;
		}

		/**
		 * Return a hash code for this <code>SamplePrincipal</code>.
		 * 
		 * <p>
		 * 
		 * @return a hash code for this <code>SamplePrincipal</code>.
		 */
		@Override
		public int hashCode() {
			return name.hashCode();
		}
	}

	private boolean authWithRadius(String host, int port, String secret, String username, char[] password) throws SocketException,
			UnknownHostException {
		RadiusClient radiusClient = new RadiusClient(new DatagramSocket(),
				InetAddress.getByName(host), secret, port, 1813,
				10);

		AttributeList attributeList = new AttributeList();

		attributeList.add(new Attr_UserName(username));
		attributeList.add(new Attr_NASPortType(Attr_NASPortType.Virtual));
		attributeList.add(new Attr_NASPort(new Long(1)));

		AccessRequest request = new AccessRequest(radiusClient, attributeList);
		request.addAttribute(new Attr_UserPassword(new String(password)));

		try {
			RadiusPacket reply = radiusClient.authenticate(request,
					new PAPAuthenticator(), 1);
			if (reply == null)
				throw new RuntimeException("Timeout authenticating user with the server"); // Request Timed-out
			
			boolean isAuthenticated = (reply instanceof AccessAccept);

			String replyMessage = (String) reply
					.getAttributeValue(Attr_ReplyMessage.TYPE);

			if (debug && replyMessage != null) {
				logger.debug("Reply Message: " + replyMessage);
			}
			String userRole = (String) reply
					.getAttributeValue("Aruba-User-Role");

			if (!isAuthenticated
					|| userRole == null
					|| (!userRole.equals("faculty") && !userRole
							.equals("student"))) {
				return false;
			} else {
				return true;
			}
		} catch (UnknownAttributeException e) {
			throw new RuntimeException(e);
		} catch (RadiusException e) {
			throw new RuntimeException(e);
		}

	}

}
