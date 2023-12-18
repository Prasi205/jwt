package com.tm.jsonwebtoken.service.impl;

import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.tm.jsonwebtoken.entity.TokenDetails;
import com.tm.jsonwebtoken.entity.TransacTokenDetails;
import com.tm.jsonwebtoken.exception.CustomJwtException;
import com.tm.jsonwebtoken.pojo.RefreshTokenPOJO;
import com.tm.jsonwebtoken.repository.TokenDetailsRepository;
import com.tm.jsonwebtoken.repository.TransacTokenDetailsRepository;
import com.tm.jsonwebtoken.request.RefreshTokenRequest;
import com.tm.jsonwebtoken.request.TokenGenerationRequest;
import com.tm.jsonwebtoken.response.TokenGenerationResponse;
import com.tm.jsonwebtoken.service.JwtService;
import com.tm.jsonwebtoken.util.JwtUtil;


/**
 * This class provides the implementation of the JwtService interface. It
 * contains methods to handle Json web token operations and saving token details
 * in database. This class interacts with JwtUtil to generate and validate
 * tokens.
 */
@Service
public class JwtServiceImpl implements JwtService {

	@Autowired
	private TokenDetailsRepository tokenDetailsRepository;
	
	@Autowired
	private TransacTokenDetailsRepository transacTokenDetailsRepository;

	@Autowired
	private JwtUtil jwtUtil;

	Logger logger = LoggerFactory.getLogger(JwtServiceImpl.class);

	/**This method is used to get the access and refresh token from jwt util class
	 * method and pass the access token and refresh token in db storing process
	 * @param tokenGenerationRequest
	 * @return TokenGenerationResponse
	 */
	public TokenGenerationResponse generateToken(TokenGenerationRequest tokenGenerationRequest) throws CustomJwtException {
		logger.info("Received request to get the access token and refresh token");
		try {
			logger.info("Get the access and refresh token from util class");
			String accessToken=jwtUtil.generateAccessToken(tokenGenerationRequest);
			String refreshToken=jwtUtil.generateRefreshToken(tokenGenerationRequest);
			String uniqueId=tokenGenerationRequest.getUniqueId();
			saveTokenDetails(uniqueId, accessToken, refreshToken);
			saveTransactionTokenDetails(uniqueId, accessToken, refreshToken);
			logger.info("Display the access and refresh token in response");
			return new TokenGenerationResponse(accessToken,refreshToken);
		} catch (Exception e) {
			logger.error("Unable to get the token details!...");
			throw new CustomJwtException("Unable to get the token details!..");
		}
		
	}
	
	/**This method is used to save the token details with created date and updated
	 * date in database
	 * 
	 * @param uniqueId
	 * @param accessToken
	 * @param refreshToken
	 * @throws CustomJwtException
	 */
	public void saveTokenDetails(String uniqueId, String accessToken, String refreshToken) throws CustomJwtException {
	    logger.info("Received the request to save/update the token details");
	    try {
	    	logger.info("Find the token details based on unique id");
	        TokenDetails existingTokenDetails = tokenDetailsRepository.findByUniqueId(uniqueId);
	        if (existingTokenDetails != null) {
	        	logger.info("Checking the unique id details is available or not");
	            existingTokenDetails.setAccessToken(accessToken);
	            existingTokenDetails.setRefreshToken(refreshToken);
	            existingTokenDetails.setUpdatedAt(new Date());
	            logger.info("Token details updated based on unique id in the database");
	            tokenDetailsRepository.save(existingTokenDetails);
	        } else {
	        	logger.info("Received the request to save the new token details");
	            TokenDetails newTokenDetails = new TokenDetails();
	            newTokenDetails.setUniqueId(uniqueId);
	            newTokenDetails.setAccessToken(accessToken);
	            newTokenDetails.setRefreshToken(refreshToken);
	            newTokenDetails.setCreatedAt(new Date());
	            newTokenDetails.setUpdatedAt(new Date());
	            logger.info("New token details saved in the database");
	            tokenDetailsRepository.save(newTokenDetails);
	        }
	    } catch (Exception e) {
	        logger.error("Unable to save/update the token details in the database!...");
	        throw new CustomJwtException("Unable to save/update the details!..");
	    }
	}

	
	public void saveTransactionTokenDetails(String uniqueId, String accessToken, String refreshToken) throws CustomJwtException {
		logger.info("Received the request to save the transaction token details");
		try {
			logger.info("Set the transac token details");
			TransacTokenDetails saveTransacTokenDetails = new TransacTokenDetails();
			saveTransacTokenDetails.setUniqueId(uniqueId);
			saveTransacTokenDetails.setAccessToken(accessToken);
			saveTransacTokenDetails.setRefreshToken(refreshToken);
			saveTransacTokenDetails.setCreatedAt(new Date());
			saveTransacTokenDetails.setUpdatedAt(new Date());
			logger.info("Transaction token details are saved in database");
			transacTokenDetailsRepository.save(saveTransacTokenDetails);
		} catch (Exception e) {
			logger.error("Unable to save the transaction token details in database!...");
			throw new CustomJwtException("Unable to save the details!..");
		}
	}

	/**This method is used to generate the new access and refresh token
	 * @param refreshTokenRequest
	 * @return RefreshTokenPOJO
	 * @throws Exception 
	 */
	public RefreshTokenPOJO regenerateTokens(RefreshTokenRequest refreshTokenRequest) {
		logger.info("Received the request to validate the access and refresh token");
		RefreshTokenPOJO refreshTokenResponse = new RefreshTokenPOJO();
		try {
			logger.info("Check the access token is expired or not");
			boolean isAccessTokenvalid = jwtUtil.isValidAccessToken(refreshTokenRequest.getAccessToken(),
					refreshTokenRequest.getUniqueId(), refreshTokenRequest.getSecretKey());
			if (isAccessTokenvalid) {
				logger.info("Given details are valid, So regenrate tokens and return in response");
				TokenGenerationRequest tokenGenerationRequest = new TokenGenerationRequest();
				tokenGenerationRequest.setUniqueId(refreshTokenRequest.getUniqueId());
				tokenGenerationRequest.setSecretKey(refreshTokenRequest.getSecretKey());
				tokenGenerationRequest.setAccessTokenTime(refreshTokenRequest.getAccessTokenTime());
				tokenGenerationRequest.setRefreshTokenTime(refreshTokenRequest.getRefreshTokenTime());
				
				TokenGenerationResponse generateToken = generateToken(tokenGenerationRequest);
				refreshTokenResponse.setAccessToken(generateToken.getAccessToken());
				refreshTokenResponse.setRefreshToken(generateToken.getRefreshToken());
			} else {
				logger.error("Refresh token is expired");
				throw new CustomJwtException("Refresh Token is expired");
			}

		} catch (Exception e) {
			logger.error("Error refreshing token");
			throw new CustomJwtException("Error refreshing token");
		}
		return refreshTokenResponse;
	}

}
