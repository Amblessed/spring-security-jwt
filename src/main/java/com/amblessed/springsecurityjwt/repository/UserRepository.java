package com.amblessed.springsecurityjwt.repository;



/*
 * @Project Name: spring-security-jwt
 * @Author: Okechukwu Bright Onwumere
 * @Created: 26-Sep-24
 */


import com.amblessed.springsecurityjwt.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByEmail(String email);
}
