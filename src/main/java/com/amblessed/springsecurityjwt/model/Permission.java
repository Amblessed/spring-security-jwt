package com.amblessed.springsecurityjwt.model;



/*
 * @Project Name: spring-security-jwt
 * @Author: Okechukwu Bright Onwumere
 * @Created: 26-Sep-24
 */


import lombok.Getter;
import lombok.RequiredArgsConstructor;


@RequiredArgsConstructor
public enum Permission {

    ADMIN_READ("admin:read"),
    ADMIN_CREATE("admin:create"),
    MEMBER_READ("management:read"),
    MEMBER_CREATE("management:create");

    @Getter
    private final String permission;
}
