package com.amblessed.springsecurityjwt.authentication;



/*
 * @Project Name: spring-security-jwt
 * @Author: Okechukwu Bright Onwumere
 * @Created: 26-Sep-24
 */


import com.amblessed.springsecurityjwt.model.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@Builder
@NoArgsConstructor
public class RegisterRequest {


    private String firstName;
    private String lastName;
    private String email;
    private String password;
    private Role role;
}
