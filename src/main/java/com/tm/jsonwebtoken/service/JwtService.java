package com.tm.jsonwebtoken.service;

import com.tm.jsonwebtoken.exception.CustomJwtException;
import com.tm.jsonwebtoken.pojo.TokenGenerationPOJO;
import com.tm.jsonwebtoken.request.RefreshTokenRequest;
import com.tm.jsonwebtoken.request.TokenGenerationRequest;
import com.tm.jsonwebtoken.request.TokenValidationRequest;

public interface JwtService {
	
	public TokenGenerationPOJO generateToken(TokenGenerationRequest tokenGenerationRequest) 
			  throws CustomJwtException;
	
	public boolean validateToken(TokenValidationRequest tokenValidationRequest);
	
	public TokenGenerationPOJO regenerateTokens(RefreshTokenRequest refreshTokenRequest);

}
