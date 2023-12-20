package com.tm.jsonwebtoken.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.tm.jsonwebtoken.exception.CustomJwtException;
import com.tm.jsonwebtoken.pojo.RefreshTokenPOJO;
import com.tm.jsonwebtoken.request.RefreshTokenRequest;
import com.tm.jsonwebtoken.request.TokenGenerationRequest;
import com.tm.jsonwebtoken.request.TokenValidationRequest;
import com.tm.jsonwebtoken.response.JwtResponsePOJO;
import com.tm.jsonwebtoken.response.TokenGenerationResponse;
import com.tm.jsonwebtoken.service.JwtService;

/**Controller class for handling JSON web token generation and validation requests. */
@RestController
@RequestMapping(value = "/jwt")
public class JwtController {

	@Autowired
	private JwtService jwtService;

	Logger logger = LoggerFactory.getLogger(JwtController.class);

	/**Handles the generation of access and refresh tokens based on the received request.
	 * @param tokenGenerationRequest
	 * @return JwtResponsePOJO
	 */
	@PostMapping("/generateToken")
	public JwtResponsePOJO generateToken(@RequestBody TokenGenerationRequest tokenGenerationRequest) {
		logger.info("Received request to generate token");
		JwtResponsePOJO jwtResponsePOJO = new JwtResponsePOJO();
		try {
			logger.info("Token generation request received successfully");
			TokenGenerationResponse tokenGenerationResponse=jwtService.generateToken(tokenGenerationRequest);
			jwtResponsePOJO.response("Tokens are generated", tokenGenerationResponse, true);
		} catch (Exception e) {
			logger.error("Unable to generate token");
			throw new CustomJwtException("Unable to generate token");
		}
		return jwtResponsePOJO;	
	}

	/**Handles the token validation expiration based on the received request.
	 * @param tokenValidationRequest
	 * @return boolean
	 */
	@PostMapping("/validateToken")
	public ResponseEntity<String> validateTokenController(@RequestBody TokenValidationRequest tokenValidationRequest) {
	    try {
	        boolean isAccessTokenValid = jwtService.validateToken(tokenValidationRequest);
	        if (isAccessTokenValid) {
	        	logger.info("Access token is valid");
	            return ResponseEntity.ok("Access token is valid");
	        } else {
	        	logger.error("Invalid user and Token");
	            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Access token is invalid");
	        }
	    } catch (CustomJwtException e) {
	    	logger.error("Unable to validate token");
	        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Unable to validate token");
	    }
	}
	
	/**Handles the new access and refresh token generation based on the received request
	 * @param refreshTokenRequest
	 * @return JwtResponsePOJO
	 * @throws Exception 
	 */
	@PostMapping("/regenerateTokens")
	public JwtResponsePOJO regenerateTokens(@RequestBody RefreshTokenRequest refreshTokenRequest) {
		logger.info("Received new access and refresh token generation request");
		JwtResponsePOJO jwtResponsePOJO = new JwtResponsePOJO();
		try {
			logger.info("Token validation and regenerate tokens request received successfully");
			RefreshTokenPOJO refreshTokenResponse = jwtService.regenerateTokens(refreshTokenRequest);
			if (StringUtils.hasText(refreshTokenResponse.getAccessToken())
					&& StringUtils.hasText(refreshTokenResponse.getRefreshToken())) {
				logger.info("Tokens are received");
				jwtResponsePOJO.response("Tokens are", refreshTokenResponse, true);
			} else {
				logger.error("Unabele to get response");
				jwtResponsePOJO.response("Unabele to get response", null, false);
			}

		} catch (Exception e) {
			e.printStackTrace();
			logger.error("Unable to validate the request");
			throw new CustomJwtException("Unable to validate the request");
		}
		return jwtResponsePOJO;
	}
}
