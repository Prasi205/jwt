package com.tm.jsonwebtoken.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.tm.jsonwebtoken.entity.TransacTokenDetails;

public interface TransacTokenDetailsRepository extends JpaRepository<TransacTokenDetails, Integer> {

}
