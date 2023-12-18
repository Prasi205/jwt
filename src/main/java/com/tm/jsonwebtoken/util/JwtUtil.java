package com.tm.jsonwebtoken.util;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.tm.jsonwebtoken.entity.TokenDetails;
import com.tm.jsonwebtoken.repository.TokenDetailsRepository;
import com.tm.jsonwebtoken.request.TokenGenerationRequest;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

/**
 * This Utility class handles the JSON Web token operation like generate the
 * access and refreshtoken, validate the tokens
 */
@Component
public class JwtUtil {

	@Autowired
	private TokenDetailsRepository tokenDetailsRepository;

	private static final Logger logger = LoggerFactory.getLogger(JwtUtil.class);

	/**
	 * This method is used to generate the access token with expiry date
	 * 
	 * @param uniqueId
	 * @param secretKey
	 * @param accessTokenTime
	 * @return String
	 */
	public String generateAccessToken(TokenGenerationRequest tokenGenerationRequest) {
		logger.info("Received request to generate the access token");
		try {
			Map<String, Object> claims = new HashMap<>();

			logger.info("Access token is successfully generated");
			
			return Jwts.builder().setClaims(claims).setSubject(tokenGenerationRequest.getUniqueId())
					.setIssuedAt(new Date(System.currentTimeMillis()))
					.setExpiration(new Date(System.currentTimeMillis() + tokenGenerationRequest.getAccessTokenTime()))
					.signWith(SignatureAlgorithm.HS512, tokenGenerationRequest.getSecretKey())
					.compact();
		} catch (Exception e) {
			logger.error("Unable to generate the access token");
			return "Unable to generate access token";
		}
		
	}

	/**
	 * This method is used to generate the refresh token with expiry date and time
	 * 
	 * @param tokenGenerationRequest
	 * @return String
	 */
	public String generateRefreshToken(TokenGenerationRequest tokenGenerationRequest) {
		logger.info("Received the request to generate the refresh token");
		try {
			Map<String, Object> claims = new HashMap<>();

			logger.info("Refresh token is successfully generated");
			return Jwts.builder().setClaims(claims).setSubject(tokenGenerationRequest.getUniqueId())
					.setIssuedAt(new Date(System.currentTimeMillis()))
					.setExpiration(new Date(System.currentTimeMillis() + tokenGenerationRequest.getRefreshTokenTime()))
					.signWith(SignatureAlgorithm.HS512, tokenGenerationRequest.getSecretKey())
					.compact();
		} catch (Exception e) {
			logger.error("Unable to generate the refresh token");
			return "Unable to generate refresh token";
		}
	}

	/**
	 * This method is used to get the token details based on unique id and token and
	 * also checking the token is expiry or not
	 * 
	 * @param accessToken
	 * @param uniqueId
	 * @param secretKey
	 * @return boolean
	 */
	public boolean isValidAccessToken(String accessToken, String uniqueId, String secretKey) {
		logger.info("Received the request to validate the access token is expired or not");
		try {
			logger.info("Received the request to get the token details based on uniqueId and access token");
			TokenDetails existingTokenDetails = tokenDetailsRepository.findByUniqueIdAndAccessToken(uniqueId,
					accessToken);
			if (Objects.nonNull(existingTokenDetails)) {
				logger.info("Validate expiration time of the access token");
				isAccessTokenExpired(secretKey, existingTokenDetails);
				logger.info("Valid User and Token");
				return true;
			} else {
				logger.error("Invalid User and Token");
				return false;
			}
		}catch (Exception exception) {
			logger.error("Unable to validate access token");
			return false;
		}
	}

	private void isAccessTokenExpired(String secretKey, TokenDetails existingTokenDetails) {
		logger.info("Received the request to validate the access token");
		try {
			Jwts.parser().setSigningKey(secretKey).parseClaimsJws(existingTokenDetails.getAccessToken()).getBody();
			logger.info("Access token is not expired");
		} catch (ExpiredJwtException expiredJwtException) {
			logger.error("Access token is expired");
		}
	}
	
}
