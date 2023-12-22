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
import com.tm.jsonwebtoken.exception.CustomJwtException;
import com.tm.jsonwebtoken.repository.TokenDetailsRepository;
import com.tm.jsonwebtoken.request.RefreshTokenRequest;
import com.tm.jsonwebtoken.request.TokenGenerationRequest;
import com.tm.jsonwebtoken.request.TokenValidationRequest;

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

	/**This method is used to generate the access token with expiry date
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
					.signWith(SignatureAlgorithm.HS512, tokenGenerationRequest.getSecretKey()).compact();
		} catch (Exception e) {
			logger.error("Unable to generate the access token");
			return "Unable to generate access token";
		}

	}

	/**This method is used to generate the refresh token with expiry date and time
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
					.signWith(SignatureAlgorithm.HS512, tokenGenerationRequest.getSecretKey()).compact();
		} catch (Exception e) {
			logger.error("Unable to generate the refresh token");
			return "Unable to generate refresh token";
		}
	}

	/**This method is used to get the token details based on unique id and token and
	 * also checking the token is expiry or not
	 * @param accessToken
	 * @param uniqueId
	 * @param secretKey
	 * @return boolean
	 */
	private boolean isValidUser(String uniqueId,String token) {
		logger.info("Received the request to validate the access token is expired or not");
		try {
			logger.info("Received the request to get the token details based on uniqueId and access token");
			TokenDetails existingTokenDetails = tokenDetailsRepository.findByUniqueIdAndAccessToken(uniqueId,
					                  token);
			if (Objects.nonNull(existingTokenDetails)) {
				logger.info("Valid user and Token");
				return true;
			} else {
				logger.error("Invalid User and Token");
				return false;
			}
		} catch (Exception exception) {
			logger.error("Unable to validate access token");
			throw new CustomJwtException("Unable to validate access token");
		}
	}

	/**This method is used to check the access token is expired or not
	 * @param secretKey
	 * @param existingTokenDetails
	 * @return String
	 */
	private boolean isTokenExpired(String secretKey, String token) {
		logger.info("Received the request to validate the access token");
		try {
			Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody();
			logger.info("Token is not expired");
			return true;
		} catch (ExpiredJwtException expiredJwtException) {
			logger.error("Token is expired");
			return false;
		}
	}
	
	/**This method is used to validate the accesstoken and user
	 * @param tokenValidationRequest
	 * @return boolean
	 */
	public boolean validateToken(TokenValidationRequest tokenValidationRequest) {
		logger.info("Received request to validate the user and access token");
		try {
			boolean isValidUser = isValidUser(tokenValidationRequest.getUniqueId(),
					tokenValidationRequest.getAccessToken());
			boolean isTokenExpired = isTokenExpired(tokenValidationRequest.getSecretKey(),
					tokenValidationRequest.getAccessToken());
			logger.info("User and token validation is successfully acheived");
			return isValidUser && isTokenExpired;
		} catch (Exception e) {
			logger.error("Unable to validate the user and token details");
			return false;
		}
	}

	/**This method is used to valid the user and refresh token
	 * @param refreshTokenRequest
	 * @return boolean
	 */
	public boolean validateUserAndRefreshToken(RefreshTokenRequest refreshTokenRequest) {
		logger.info("Received request to validate the user and refresh token");
		try {
			boolean isValidUser = isValidUser(refreshTokenRequest.getUniqueId(),refreshTokenRequest.getRefreshToken());
			if (isValidUser) {
				isTokenExpired(refreshTokenRequest.getSecretKey(), refreshTokenRequest.getRefreshToken());
				logger.info("Valid User and refresh Token");
				return true;
			}else {
				logger.error("Invalid User and refresh Token");
				return false;
			}
		} catch (Exception e) {
			logger.error("Unable to validate the token and user");
			return false;
		}	
	}
	
}
