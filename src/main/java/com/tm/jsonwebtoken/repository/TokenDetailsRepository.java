package com.tm.jsonwebtoken.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.tm.jsonwebtoken.entity.TokenDetails;

public interface TokenDetailsRepository extends JpaRepository<TokenDetails, Integer>{
	
	TokenDetails findByUniqueId(String uniqueId);
	
	TokenDetails findByUniqueIdAndAccessToken(String uniqueId, String token);

}
