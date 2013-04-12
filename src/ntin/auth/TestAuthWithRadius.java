package ntin.auth;

import java.io.IOException;
import java.net.UnknownHostException;

import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

public class TestAuthWithRadius {

	/**
	 * @param args
	 * @throws IOException
	 * @throws UnknownHostException
	 */
	public static void main(String[] args) throws UnknownHostException,
			IOException {

		// Obtain a LoginContext, needed for authentication.
		// Tell it to use the LoginModule implementation
		// specified by the entry named "Sample" in the
		// JAAS login configuration file and to also use the
		// specified CallbackHandler.
		LoginContext lc = null;
		try {
			lc = new LoginContext("Sample", new MyCallbackHandler());
		} catch (LoginException le) {
			System.err
					.println("Cannot create LoginContext. " + le.getMessage());
			System.exit(-1);
		} catch (SecurityException se) {
			System.err
					.println("Cannot create LoginContext. " + se.getMessage());
			System.exit(-1);
		}

		// the user has 3 attempts to authenticate successfully
		int i;
		for (i = 0; i < 3; i++) {
			try {

				// attempt authentication
				lc.login();

				// if we return with no exception,
				// authentication succeeded
				break;

			} catch (LoginException le) {

				System.err.println("Authentication failed:");
				System.err.println("  " + le.getMessage());
				try {
					Thread.sleep(3000);
				} catch (Exception e) {
					// ignore
				}

			}
		}

		// did they fail three times?
		if (i == 3) {
			System.out.println("Sorry");
			System.exit(-1);
		}

		System.out.println("Authentication succeeded!");

	}

}
