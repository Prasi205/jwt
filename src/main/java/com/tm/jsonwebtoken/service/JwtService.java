package com.tm.jsonwebtoken.service;

import com.tm.jsonwebtoken.exception.CustomJwtException;
import com.tm.jsonwebtoken.pojo.RefreshTokenPOJO;
import com.tm.jsonwebtoken.request.RefreshTokenRequest;
import com.tm.jsonwebtoken.request.TokenGenerationRequest;
import com.tm.jsonwebtoken.response.TokenGenerationResponse;

public interface JwtService {
	
	public TokenGenerationResponse generateToken(TokenGenerationRequest tokenGenerationRequest) 
			  throws CustomJwtException;
	
	public RefreshTokenPOJO regenerateTokens(RefreshTokenRequest refreshTokenRequest);

}
