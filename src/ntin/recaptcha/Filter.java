package ntin.recaptcha;

import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;
import net.tanesha.recaptcha.ReCaptchaImpl;
import net.tanesha.recaptcha.ReCaptchaResponse;

public class Filter implements javax.servlet.Filter {

	public void init(FilterConfig config) throws ServletException {
	}

	public void destroy() {
	}

	public void doFilter(ServletRequest request, ServletResponse response,
			FilterChain chain) throws IOException, ServletException {

		String remoteAddr = request.getRemoteAddr();
		ReCaptchaImpl reCaptcha = new ReCaptchaImpl();
		reCaptcha.setPrivateKey("6Le61d0SAAAAALiszHSliQNZQKV1l1DFi6P82cXy");

		String challenge = request.getParameter("recaptcha_challenge_field");
		
		if(challenge == null) {
			if(request.getParameter("j_username") != null) {
				// seems like an attempt to by-pass the recaptcha challenge; stop processing
				return;
			}
			else {
				// the first request to the login page; let it go
				chain.doFilter(request, response);
				return;
			}
		}
		
		// normal request after credential entered
		
		String uresponse = request.getParameter("recaptcha_response_field");
		ReCaptchaResponse reCaptchaResponse = reCaptcha.checkAnswer(remoteAddr,
				challenge, uresponse);

		if (reCaptchaResponse.isValid()) {
			chain.doFilter(request, response);
		}
	}

}
